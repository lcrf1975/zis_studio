import streamlit as st
import json
import requests
import time
import re
from requests.auth import HTTPBasicAuth
from jsonpath_ng import parse 

# ==========================================
# 0. SYSTEM SETUP
# ==========================================

# 1. Graphviz Check
try:
    import graphviz
    HAS_GRAPHVIZ = True
except ImportError:
    HAS_GRAPHVIZ = False

# 2. Code Editor Check
try:
    from code_editor import code_editor
    HAS_EDITOR = True
except ImportError:
    HAS_EDITOR = False

# 3. Rerun Helper
def safe_rerun():
    try:
        if hasattr(st, "rerun"): st.rerun()
        elif hasattr(st, "experimental_rerun"): st.experimental_rerun()
    except: pass

# 4. Sanitizer
def clean_flow_logic(flow_data):
    clean = flow_data.copy()
    forbidden_keys = ["zis_template_version", "resources", "name", "description", "type", "properties"]
    for key in forbidden_keys:
        if key in clean: del clean[key]
    return clean

# ==========================================
# 1. EMBEDDED ENGINE
# ==========================================
class ZISFlowEngine:
    def __init__(self, flow_definition, input_data, connections, configs):
        self.flow = flow_definition
        self.context = {
            "input": input_data,
            "connections": connections,
            "config": configs,
            "flow_name": flow_definition.get("Comment", "Local Flow")
        }
        self.logs = []
        self.visited_states = []

    def log(self, step, message, status="INFO"):
        entry = f"[{time.strftime('%H:%M:%S')}] {step}: {message} ({status})"
        self.logs.append(entry)

    def resolve_path(self, path, data):
        if not isinstance(path, str) or not path.startswith("$."): return path
        try:
            matches = parse(path.replace("$.", "")).find(data)
            return matches[0].value if matches else None
        except: return None

    def interpolate(self, text):
        if not isinstance(text, str): return text
        for ph in re.findall(r'\{\{(.*?)\}\}', text):
            val = self.resolve_path(ph, self.context)
            text = text.replace(f"{{{{{ph}}}}}", str(val))
        return text

    def run_action(self, state_name, state_def):
        action_name = state_def.get("ActionName", "Unknown")
        params = {}
        for k, v in state_def.get("Parameters", {}).items():
            key = k[:-2] if k.endswith(".$") else k
            val = self.resolve_path(v, self.context) if k.endswith(".$") else self.interpolate(v)
            params[key] = val

        self.log(state_name, f"Action: {action_name}", "RUNNING")
        
        url = params.get("url", "")
        method = params.get("method", "GET")
        
        if url:
            try:
                resp = requests.request(method, url, json=params.get("body"))
                self.log(state_name, f"API {resp.status_code}", "SUCCESS")
                return resp.json() if resp.content else {}
            except Exception as e:
                self.log(state_name, f"Error: {e}", "ERROR")
                return {"error": str(e)}
        else:
            self.log(state_name, "Mock Mode (No URL)", "WARNING")
            return {"mock": True, "params": params}

    def run(self):
        flow_def = self.flow.get("definition", self.flow)
        curr = flow_def.get("StartAt")
        states = flow_def.get("States", {})
        
        self.log("START", f"Flow: {self.context.get('flow_name', 'Local')}")
        steps = 0
        
        while curr and steps < 50:
            steps += 1
            self.visited_states.append(curr)
            state = states.get(curr)
            if not state: break

            sType = state.get("Type")
            if sType == "Action":
                res = self.run_action(curr, state)
                if "ResultPath" in state:
                    self.context[state["ResultPath"].split(".")[-1]] = res
                curr = state.get("Next")
            elif sType == "Choice":
                curr = state.get("Default")
                for rule in state.get("Choices", []):
                    val = self.resolve_path(rule.get("Variable"), self.context)
                    if str(val) == str(rule.get("StringEquals")):
                        curr = rule.get("Next")
                        break
            elif sType == "Pass":
                if "Result" in state:
                    self.context[state.get("ResultPath", "$.result").split(".")[-1]] = state["Result"]
                curr = state.get("Next")
            elif sType == "Wait":
                time.sleep(float(state.get("Seconds", 1)))
                curr = state.get("Next")
            elif sType in ["Succeed", "Fail"]:
                break
            
            if state.get("End"): break
            
        return self.logs, self.context, self.visited_states

# ==========================================
# 2. APP UI CONFIG
# ==========================================
st.set_page_config(page_title="ZIS Studio", layout="wide", page_icon="⚡")

if "flow_json" not in st.session_state:
    st.session_state["flow_json"] = {
        "StartAt": "StartStep",
        "States": {"StartStep": {"Type": "Pass", "End": True}}
    }

if "editor_key" not in st.session_state:
    st.session_state["editor_key"] = 0 

if "editor_content" not in st.session_state:
    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)

text_settings = ["zd_subdomain", "zd_email", "zd_token"]
for key in text_settings:
    if key not in st.session_state: st.session_state[key] = ""

def get_auth():
    if st.session_state.zd_email and st.session_state.zd_token:
        return HTTPBasicAuth(f"{st.session_state.zd_email}/token", st.session_state.zd_token)
    return None

def get_base_url():
    sub = st.session_state.zd_subdomain
    return f"https://{sub}.zendesk.com/api/services/zis/registry" if sub else ""

def test_connection():
    try:
        sub = st.session_state.zd_subdomain
        if not sub: return False, "❌ Missing Subdomain"
        url = f"https://{sub}.zendesk.com/api/v2/users/me.json"
        response = requests.get(url, auth=get_auth())
        if response.status_code == 200: return True, f"✅ Connected"
        return False, f"❌ Error: {response.status_code}"
    except Exception as e: return False, f"❌ Error: {str(e)}"

# ==========================================
# 3. VISUALIZATION FUNCTION (UNIVERSAL THEME)
# ==========================================
def render_flow_graph(flow_def, highlight_path=None):
    if not HAS_GRAPHVIZ:
        st.warning("⚠️ Graphviz not installed.")
        return
    
    try:
        dot = graphviz.Digraph(comment='ZIS Flow')
        dot.attr(rankdir='TB', splines='ortho')
        
        # [THEME FIX] Transparent background + High Contrast colors
        # This makes the graph readable on BOTH Dark and Light modes.
        dot.attr(bgcolor='transparent')
        
        # Nodes: White background, Black text (Always readable)
        dot.attr('node', shape='box', style='rounded,filled', fillcolor='white', fontcolor='black', fontname='Arial', fontsize='12')
        
        # Edges: Dark Grey (Visible on white, readable on dark grey)
        dot.attr('edge', color='#555555', fontcolor='#555555')

        visited_set = set(highlight_path) if highlight_path else set()
        
        start_node = flow_def.get("StartAt")
        # Start Node: Green
        dot.node("START", "Start", shape="circle", fillcolor="#4CAF50", fontcolor="white", width="0.8")
        
        if start_node: dot.edge("START", start_node)

        for name, state in flow_def.get("States", {}).items():
            # Default: White
            fill = "white"
            penwidth = "1"
            
            # Active Path: Green
            if name in visited_set: 
                fill = "#C8E6C9"
                penwidth = "2"
                if highlight_path and name == highlight_path[-1]: fill = "#81C784"
            
            label = f"{name}\n({state.get('Type','?')})"
            dot.node(name, label, fillcolor=fill, penwidth=penwidth)
            
            if "Next" in state: dot.edge(name, state["Next"])
            elif state.get("Type") == "Choice":
                for rule in state.get("Choices", []):
                    dot.edge(name, rule.get("Next"), label="If Match")
                if "Default" in state: dot.edge(name, state["Default"], label="Default")
            elif state.get("End"):
                # End Node: Dark Grey
                dot.node("END", "End", shape="doublecircle", fillcolor="#333333", fontcolor="white", width="0.6")
                dot.edge(name, "END")
        
        st.graphviz_chart(dot)
    except Exception as e:
        st.error(f"Graph Error: {e}")

# ==========================================
# 4. MAIN TABS
# ==========================================
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🔌 Connection", 
    "📥 Import", 
    "🚀 Deploy", 
    "📝 Code", 
    "🎨 Designer", 
    "🐞 Debug"
])

# TAB 1: CONNECTION
with tab1:
    st.header("Connection")
    c1, c2 = st.columns(2)
    with c1:
        st.text_input("Subdomain", key="zd_subdomain")
        st.text_input("Email", key="zd_email")
        st.text_input("Token", key="zd_token", type="password")
        if st.button("Test", key="btn_test"):
            ok, msg = test_connection()
            if ok: 
                st.session_state["is_connected"] = True
                st.success(msg)
            else: st.error(msg)

# TAB 2: IMPORT
with tab2:
    st.header("Load Flows")
    if not st.session_state.get("is_connected"):
        st.warning("Please connect first.")
    else:
        st.markdown("**Find every Flow in your account.**")
        
        if st.button("🚀 Start Deep Scan", key="btn_deep_scan"):
            results = []
            prog = st.progress(0)
            status = st.empty()
            try:
                status.text("Fetching Integrations...")
                resp = requests.get(f"{get_base_url()}/integrations", auth=get_auth())
                
                if resp.status_code == 401:
                     st.error("🚨 401 Unauthorized. ZIS might be disabled.")
                elif resp.status_code != 200: st.error(f"Failed: {resp.status_code}")
                else:
                    ints = resp.json().get("integrations", [])
                    total = len(ints)
                    for i, obj in enumerate(ints):
                        name = obj["name"]
                        status.text(f"Scanning {i+1}/{total}: {name}")
                        prog.progress((i+1)/total)
                        
                        r_bun = requests.get(f"{get_base_url()}/{name}/bundles", auth=get_auth())
                        if r_bun.status_code == 200:
                            for b in r_bun.json().get("bundles", []):
                                results.append({
                                    "int": name, 
                                    "bun": b["name"],
                                    "uuid": b.get("uuid", "")
                                })
                        time.sleep(0.05)
                    st.session_state["scan_results"] = results
                    if not results: st.warning("Found 0 bundles.")
                    else: st.success(f"Found {len(results)} bundles.")
            except Exception as e: st.error(str(e))

        if "scan_results" in st.session_state and st.session_state["scan_results"]:
            res = st.session_state["scan_results"]
            if res:
                sel_idx = st.selectbox("Select Bundle", range(len(res)), format_func=lambda i: f"{res[i]['int']} -> {res[i]['bun']}")
                sel_item = res[sel_idx]
                
                if st.button("Load Flow", key="btn_load_flow"):
                    identifier = sel_item['uuid'] if sel_item['uuid'] else sel_item['bun']
                    url = f"{get_base_url()}/{sel_item['int']}/bundles/{identifier}"
                    
                    with st.spinner("Downloading Bundle..."):
                        r = requests.get(url, auth=get_auth())
                        
                        if r.status_code == 200:
                            data = r.json()
                            found = False
                            for k, v in data.get("resources", {}).items():
                                if "Flow" in v.get("type", ""):
                                    raw = v["properties"]["definition"]
                                    st.session_state["flow_json"] = clean_flow_logic(raw)
                                    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                                    st.session_state["current_bundle_name"] = sel_item['bun']
                                    st.session_state["current_int_name"] = sel_item['int']
                                    st.session_state["editor_key"] += 1
                                    
                                    st.success("Loaded Successfully!")
                                    found = True
                                    time.sleep(0.5)
                                    safe_rerun()
                                    break
                            if not found: st.warning("Bundle loaded, but no Flow inside.")
                        else: 
                            st.error(f"Failed to fetch content (Status {r.status_code}).")

# TAB 3: DEPLOY
with tab3:
    st.header("Deploy")
    if not st.session_state.get("is_connected"):
        st.warning("Please connect first.")
    else:
        sub = st.session_state.get("zd_subdomain", "sub")
        valid_int = f"zis_playground_{sub.lower().strip()}"
        st.info(f"Target Integration: `{valid_int}`")
        
        def_bun = st.session_state.get("current_bundle_name", "my_new_flow")
        dep_bun = st.text_input("Bundle Name", value=def_bun, key="dep_bun_name")
        
        if st.button("Deploy to Production", type="primary", key="btn_deploy_prod"):
            with st.spinner("Deploying..."):
                try:
                    # 1. Create/Check Integration (Idempotent)
                    requests.post(f"{get_base_url()}/integrations", auth=get_auth(), 
                                  json={"name": valid_int, "display_name": valid_int}, 
                                  headers={"Content-Type": "application/json"})
                    
                    # 2. Upload Bundle
                    safe_bun = dep_bun.lower().replace("-", "_").replace(" ", "")
                    res_name = f"{safe_bun}_flow"
                    clean_def = clean_flow_logic(st.session_state["flow_json"])
                    
                    payload = {
                        "zis_template_version": "2019-10-14",
                        "name": safe_bun,
                        "resources": {
                            res_name: {
                                "type": "ZIS::Flow",
                                "properties": {"name": res_name, "definition": clean_def}
                            }
                        }
                    }
                    
                    url = f"{get_base_url()}/{valid_int}/bundles"
                    r = requests.post(url, auth=get_auth(), json=payload, headers={"Content-Type": "application/json"})
                    
                    if r.status_code in [200, 201]:
                        st.balloons()
                        st.success(f"Deployed: {safe_bun}")
                    else:
                        st.error(f"Failed: {r.status_code}")
                        st.write(r.text)
                except Exception as e: st.error(str(e))

# TAB 4: CODE
with tab4:
    st.header("JSON Editor")
    dynamic_key = f"code_editor_{st.session_state['editor_key']}"
    
    if HAS_EDITOR:
        btn_settings = [{"name": "Apply", "feather": "Save", "primary": True, "hasText": True, "alwaysOn": True, "commands": ["submit"]}]
        response = code_editor(st.session_state.get("editor_content", ""), lang="json", height=[20, 30], buttons=btn_settings, key=dynamic_key)
        if response['type'] == "submit" and response['text']:
            try:
                js = json.loads(response['text'])
                if "definition" in js: js = js["definition"]
                st.session_state["flow_json"] = clean_flow_logic(js)
                st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                st.success("Updated!")
                time.sleep(0.1); safe_rerun()
            except Exception as e: st.error(f"Invalid JSON: {e}")
    else:
        st.warning("⚠️ Install `streamlit-code-editor` for highlighting.")
        txt = st.text_area("Flow", value=st.session_state.get("editor_content",""), height=600, key=dynamic_key)
        if st.button("💾 Apply", key="btn_apply_code"):
            try:
                js = json.loads(txt)
                if "definition" in js: st.session_state["flow_json"] = clean_flow_logic(js["definition"])
                else: st.session_state["flow_json"] = clean_flow_logic(js)
                st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                st.success("Updated!")
                time.sleep(0.1); safe_rerun()
            except Exception as e: st.error(f"Invalid JSON: {e}")

# TAB 5: VISUAL
with tab5:
    c1, c2 = st.columns([1, 2])
    curr = st.session_state["flow_json"]
    states = curr.get("States", {})
    keys = list(states.keys())
    
    with c1:
        st.subheader("Step Editor")
        sel = st.selectbox("Select Step", ["(New)"] + keys, key="vis_sel")
        
        if sel == "(New)":
            new_name = st.text_input("Name", key="new_step_name")
            new_type = st.selectbox("Type", ["Pass", "Action", "Choice", "Wait", "Succeed", "Fail"], key="new_step_type")
            if st.button("Add", key="btn_add_step"):
                if new_name and new_name not in states:
                    new_def = {"Type": new_type, "End": True}
                    if new_type == "Wait": new_def["Seconds"] = 5
                    elif new_type == "Pass": new_def["ResultPath"] = "$.result"
                    elif new_type == "Choice": new_def["Choices"] = []; new_def["Default"] = new_name
                    elif new_type == "Action": new_def["ActionName"] = "zis:common:action:fetch"; new_def["Parameters"] = {}
                    else: new_def["End"] = True
                    st.session_state["flow_json"]["States"][new_name] = new_def
                    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                    safe_rerun()
        
        elif sel in states:
            data = states[sel]
            sType = data.get("Type")
            st.markdown(f"### {sel} `[{sType}]`")
            k = f"_{sel}"
            
            if sType not in ["Succeed", "Fail", "Choice"]:
                is_end = st.checkbox("End?", value=data.get("End", False), key=f"end{k}")
                if is_end: 
                    data["End"] = True
                    data.pop("Next", None)
                else:
                    data.pop("End", None)
                    opts = [x for x in keys if x != sel]
                    curr_next = data.get("Next", "")
                    idx = opts.index(curr_next) if curr_next in opts else 0
                    if opts: data["Next"] = st.selectbox("Next", opts, index=idx, key=f"next{k}_{len(opts)}")

            if sType == "Action":
                data["ActionName"] = st.text_input("Action Name", value=data.get("ActionName", ""), key=f"an{k}")
                p_str = json.dumps(data.get("Parameters", {}), indent=2)
                p_new = st.text_area("Parameters JSON", value=p_str, height=100, key=f"ap{k}")
                try: data["Parameters"] = json.loads(p_new)
                except: st.error("Bad JSON")
            elif sType == "Wait":
                data["Seconds"] = st.number_input("Seconds", value=int(data.get("Seconds", 5)), key=f"ws{k}")
            elif sType == "Choice":
                opts = [x for x in keys if x!=sel]
                d_val = data.get("Default", "")
                d_idx = opts.index(d_val) if d_val in opts else 0
                if opts: data["Default"] = st.selectbox("Default Route", opts, index=d_idx, key=f"cd{k}_{len(opts)}")
                choices = data.get("Choices", [])
                for i, rule in enumerate(choices):
                    c1a, c2a = st.columns([3, 1])
                    with c1a: st.text(f"Rule {i+1}: {rule.get('Variable')}")
                    with c2a: 
                        if st.button("x", key=f"delr{k}_{i}"): choices.pop(i); safe_rerun()
                if st.button("Add Rule", key=f"addr{k}"):
                    if "Choices" not in data: data["Choices"] = []
                    data["Choices"].append({"Variable": "$.input", "StringEquals": "val", "Next": opts[0] if opts else ""})
                    safe_rerun()

            st.write("---")
            if st.button("Delete Step", key=f"del{k}"):
                del st.session_state["flow_json"]["States"][sel]
                st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                safe_rerun()
            if st.button("Save Changes", type="primary", key=f"sav{k}"):
                st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                st.success("Saved")
                safe_rerun()

    with c2:
        render_flow_graph(curr)

# TAB 6: DEBUG
with tab6:
    st.subheader("Local Debugger")
    inp = st.text_area("Input", '{"ticket": {"id": 1}}', height=200)
    if st.button("Run", key="btn_run"):
        try:
            eng = ZISFlowEngine(st.session_state["flow_json"], json.loads(inp), {}, {})
            logs, ctx, path = eng.run()
            c1, c2 = st.columns(2)
            with c1: 
                st.write("### Logs")
                for l in logs: st.text(l)
            with c2:
                st.write("### Output")
                st.json(ctx)
            st.write("### Path")
            render_flow_graph(st.session_state["flow_json"], highlight_path=path)
        except Exception as e: st.error(str(e))