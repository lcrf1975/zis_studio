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
try:
    import graphviz
    HAS_GRAPHVIZ = True
except ImportError:
    HAS_GRAPHVIZ = False

try:
    from code_editor import code_editor
    HAS_EDITOR = True
except ImportError:
    HAS_EDITOR = False

def safe_rerun():
    try:
        if hasattr(st, "rerun"): st.rerun()
        elif hasattr(st, "experimental_rerun"): st.experimental_rerun()
    except: pass

def clean_flow_logic(flow_data):
    clean = flow_data.copy()
    forbidden_keys = ["zis_template_version", "resources", "name", "description", "type", "properties"]
    for key in forbidden_keys:
        if key in clean: del clean[key]
    return clean

# ==========================================
# 1. THEME & CONFIG
# ==========================================
st.set_page_config(
    page_title="ZIS Studio Beta", 
    layout="wide", 
    page_icon="⚡",
    initial_sidebar_state="expanded"
)

# [CSS OVERRIDES]
# Only keeping the Sidebar Width adjustment.
# We removed color overrides to let Streamlit's native Dark Mode work perfectly.
st.markdown("""
<style>
    /* Widen the Sidebar */
    [data-testid="stSidebar"] {
        min-width: 450px;
        max-width: 600px;
    }
    
    /* Optional: Hide the standard Streamlit header for a cleaner look */
    header {visibility: hidden;}
    
    /* Adjust top padding */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Session State
if "flow_json" not in st.session_state:
    st.session_state["flow_json"] = {"StartAt": "StartStep", "States": {"StartStep": {"Type": "Pass", "End": True}}}
if "editor_key" not in st.session_state: st.session_state["editor_key"] = 0 
if "editor_content" not in st.session_state:
    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)

for key in ["zd_subdomain", "zd_email", "zd_token"]:
    if key not in st.session_state: st.session_state[key] = ""

# ==========================================
# 2. LOGIC ENGINE
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
                if "ResultPath" in state: self.context[state["ResultPath"].split(".")[-1]] = res
                curr = state.get("Next")
            elif sType == "Choice":
                curr = state.get("Default")
                for rule in state.get("Choices", []):
                    val = self.resolve_path(rule.get("Variable"), self.context)
                    if str(val) == str(rule.get("StringEquals")):
                        curr = rule.get("Next"); break
            elif sType == "Pass":
                if "Result" in state: self.context[state.get("ResultPath", "$.result").split(".")[-1]] = state["Result"]
                curr = state.get("Next")
            elif sType == "Wait":
                time.sleep(float(state.get("Seconds", 1)))
                curr = state.get("Next")
            elif sType in ["Succeed", "Fail"]: break
            if state.get("End"): break
        return self.logs, self.context, self.visited_states

# ==========================================
# 3. HELPERS & GRAPH
# ==========================================
def get_auth():
    return HTTPBasicAuth(f"{st.session_state.zd_email}/token", st.session_state.zd_token) if st.session_state.zd_token else None

def get_base_url():
    return f"https://{st.session_state.zd_subdomain}.zendesk.com/api/services/zis/registry" if st.session_state.zd_subdomain else ""

def test_connection():
    try:
        r = requests.get(f"https://{st.session_state.zd_subdomain}.zendesk.com/api/v2/users/me.json", auth=get_auth())
        # FIXED: Removed the emoji here so it doesn't duplicate in st.toast
        return (True, "Active") if r.status_code == 200 else (False, f"Error {r.status_code}")
    except Exception as e: return False, f"{str(e)}"

def render_flow_graph(flow_def, highlight_path=None):
    if not HAS_GRAPHVIZ: return st.warning("Graphviz missing")
    try:
        dot = graphviz.Digraph(comment='ZIS Flow')
        dot.attr(rankdir='TB', splines='ortho', bgcolor='transparent')
        
        # Neutral colors that work in both Light and Dark mode
        dot.attr('node', shape='box', style='rounded,filled', fillcolor='#f0f0f0', fontcolor='black', fontname='Arial', fontsize='12')
        dot.attr('edge', color='#888888') 
        
        visited = set(highlight_path) if highlight_path else set()
        start = flow_def.get("StartAt")
        dot.node("START", "Start", shape="circle", fillcolor="#4CAF50", fontcolor="white", width="0.8", style="filled")
        if start: dot.edge("START", start)

        for k, v in flow_def.get("States", {}).items():
            fill = "#f0f0f0"
            pen = "1"
            if k in visited:
                fill = "#C8E6C9" # Light Green
                pen = "2"
                if highlight_path and k == highlight_path[-1]: fill = "#81C784" # Darker Green
            
            dot.node(k, f"{k}\n({v.get('Type')})", fillcolor=fill, penwidth=pen)
            
            if "Next" in v: dot.edge(k, v["Next"])
            if "Default" in v: dot.edge(k, v["Default"], label="Default")
            for c in v.get("Choices", []): dot.edge(k, c.get("Next"), label="If Match")
            if v.get("End"): 
                dot.node("END", "End", shape="doublecircle", fillcolor="#333333", fontcolor="white", width="0.6", style="filled")
                dot.edge(k, "END")
        
        st.graphviz_chart(dot)
    except: pass

# ==========================================
# 4. SIDEBAR (CONNECTION)
# ==========================================
with st.sidebar:
    st.title("⚡ ZIS Settings")
    
    with st.expander("🔑 Credentials", expanded=True):
        st.text_input("Subdomain", key="zd_subdomain", help="Just the subdomain, e.g., 'z3n-demo'")
        st.text_input("Email", key="zd_email")
        st.text_input("API Token", key="zd_token", type="password")
        
        if st.button("Test Connection", use_container_width=True):
            ok, msg = test_connection()
            if ok: 
                st.session_state["is_connected"] = True
                st.toast(msg, icon="✅") # Icon is set here
            else: 
                st.toast(msg, icon="❌")
    
    st.divider()
    st.caption("v1.0 - ZIS Studio Beta")

# ==========================================
# 5. MAIN WORKSPACE
# ==========================================
st.title("ZIS Studio")

t_imp, t_code, t_vis, t_dep, t_deb = st.tabs([
    "📥 Import", 
    "📝 Code Editor", 
    "🎨 Visual Designer", 
    "🚀 Deploy", 
    "🐞 Debugger"
])

# --- TAB 1: IMPORT (STACKED) ---
with t_imp:
    st.markdown("### 🔎 Find Existing Flows")
    
    if not st.session_state.get("is_connected"):
        st.info("👈 Please connect your Zendesk account in the sidebar.")
    else:
        if st.button("🚀 Start Deep Scan", type="primary"):
            results = []
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                status_text.text("Fetching Integrations...")
                resp = requests.get(f"{get_base_url()}/integrations", auth=get_auth())
                
                if resp.status_code == 200:
                    ints = resp.json().get("integrations", [])
                    total_ints = len(ints)
                    
                    for idx, int_obj in enumerate(ints):
                        int_name = int_obj["name"]
                        status_text.text(f"Scanning {idx+1}/{total_ints}: {int_name}...")
                        progress_bar.progress((idx + 1) / total_ints)
                        
                        b_resp = requests.get(f"{get_base_url()}/{int_name}/bundles", auth=get_auth())
                        if b_resp.status_code == 200:
                            for b in b_resp.json().get("bundles", []):
                                results.append({
                                    "int": int_name, 
                                    "bun": b["name"],
                                    "uuid": b.get("uuid", "")
                                })
                        time.sleep(0.05)
                    
                    st.session_state["scan_results"] = results
                    status_text.empty()
                    progress_bar.empty()
                    if not results: st.warning("Scan complete. No bundles found.")
                    else: st.success(f"✅ Scan Complete. Found {len(results)} bundles.")
                    
                else: st.error("Failed to fetch integrations.")
            except Exception as e: st.error(str(e))

        if "scan_results" in st.session_state:
            res = st.session_state["scan_results"]
            st.divider()
            
            with st.container(border=True):
                st.subheader("Select a Flow to Load")
                sel_idx = st.selectbox("Available Flows", range(len(res)), format_func=lambda i: f"{res[i]['int']} / {res[i]['bun']}")
                
                if st.button("Load Flow", key="btn_load_final"):
                    item = res[sel_idx]
                    url = f"{get_base_url()}/{item['int']}/bundles/{item['uuid'] or item['bun']}"
                    
                    with st.spinner("Downloading code..."):
                        r = requests.get(url, auth=get_auth())
                        if r.status_code == 200:
                            found = False
                            for k, v in r.json().get("resources", {}).items():
                                if "Flow" in v.get("type", ""):
                                    st.session_state["flow_json"] = clean_flow_logic(v["properties"]["definition"])
                                    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                                    st.session_state["current_bundle_name"] = item['bun']
                                    st.session_state["editor_key"] += 1 
                                    st.toast("Flow Loaded Successfully!", icon="🎉")
                                    found = True
                                    time.sleep(0.5); safe_rerun()
                                    break
                            if not found: st.warning("No Flow resource found.")
                        else: st.error("Fetch failed. Please check permissions.")

# --- TAB 2: CODE (SMALLER) ---
with t_code:
    dynamic_key = f"code_editor_{st.session_state['editor_key']}"
    if HAS_EDITOR:
        btn_settings = [{"name": "Save", "feather": "Save", "primary": True, "hasText": True, "alwaysOn": True, "commands": ["submit"]}]
        resp = code_editor(st.session_state.get("editor_content", ""), lang="json", height=500, buttons=btn_settings, key=dynamic_key)
        if resp['type'] == "submit":
            try:
                js = json.loads(resp['text'])
                st.session_state["flow_json"] = clean_flow_logic(js["definition"] if "definition" in js else js)
                st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                st.toast("Code Saved", icon="💾"); time.sleep(0.2); safe_rerun()
            except: st.error("Invalid JSON")
    else:
        txt = st.text_area("JSON", st.session_state.get("editor_content", ""), height=500, key=dynamic_key)
        if st.button("Save", key="save_text"):
            try:
                js = json.loads(txt)
                st.session_state["flow_json"] = clean_flow_logic(js["definition"] if "definition" in js else js)
                st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                st.toast("Saved", icon="💾"); time.sleep(0.2); safe_rerun()
            except: st.error("Invalid JSON")

# --- TAB 3: DESIGNER ---
with t_vis:
    c1, c2 = st.columns([1, 2])
    curr = st.session_state["flow_json"]
    states = curr.get("States", {})
    keys = list(states.keys())
    
    with c1:
        st.subheader("🛠️ Configure Step")
        if not keys:
            st.info("Start by adding a step below.")
            selected_step = None
        else:
            selected_step = st.selectbox("Select Step to Edit", ["(Select a Step)"] + keys, key="sel_step_edit")
        
        with st.expander("➕ Add New Step", expanded=False):
            new_step_name = st.text_input("New Step Name", placeholder="e.g., CheckTicket", key="inp_new_name")
            new_step_type = st.selectbox("Step Type", ["Action", "Choice", "Wait", "Pass", "Succeed", "Fail"], key="sel_new_type")
            if st.button("Create Step", key="btn_create_step"):
                if new_step_name and new_step_name not in states:
                    new_def = {"Type": new_step_type}
                    if new_step_type == "Wait": new_def["Seconds"] = 5
                    elif new_step_type == "Pass": new_def["ResultPath"] = "$.result"
                    elif new_step_type == "Choice": 
                        new_def["Choices"] = []
                        new_def["Default"] = new_step_name 
                    elif new_step_type == "Fail": new_def["Error"] = "ErrorName"; new_def["Cause"] = "Cause"
                    elif new_step_type == "Action": new_def["ActionName"] = "zis:common:action:fetch"; new_def["Parameters"] = {}
                    else: new_def["End"] = True
                    st.session_state["flow_json"]["States"][new_step_name] = new_def
                    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                    st.success(f"Created {new_step_name}")
                    safe_rerun()
                else: st.error("Name required or already exists.")

        st.divider()
        if selected_step and selected_step != "(Select a Step)" and selected_step in states:
            step_data = states[selected_step]
            step_type = step_data.get("Type")
            st.markdown(f"### ⚙️ {selected_step} `[{step_type}]`")
            
            key_suffix = f"_{selected_step}"
            
            is_terminal = step_type in ["Succeed", "Fail", "Choice"] 
            if not is_terminal:
                is_end = st.checkbox("End Flow?", value=step_data.get("End", False), key=f"chk_is_end{key_suffix}")
                if is_end: step_data["End"] = True; step_data.pop("Next", None)
                else:
                    step_data.pop("End", None)
                    current_next = step_data.get("Next", "")
                    next_options = [opt for opt in keys if opt != selected_step]
                    if next_options:
                        if current_next in next_options: idx = next_options.index(current_next)
                        else: idx = 0
                        step_data["Next"] = st.selectbox("Go to Next", next_options, index=idx, key=f"sel_next_step{key_suffix}_{len(next_options)}")
                    else:
                        st.warning("Create another step to link to.")

            if step_type == "Action":
                step_data["ActionName"] = st.text_input("Action Name", value=step_data.get("ActionName", ""), key=f"inp_act_name{key_suffix}")
                current_params = json.dumps(step_data.get("Parameters", {}), indent=2)
                new_params = st.text_area("Parameters JSON", value=current_params, height=150, key=f"inp_act_params{key_suffix}")
                try: step_data["Parameters"] = json.loads(new_params)
                except: st.error("Invalid JSON")
            elif step_type == "Wait":
                step_data["Seconds"] = st.number_input("Wait (Sec)", min_value=1, value=int(step_data.get("Seconds", 5)), key=f"inp_wait_sec{key_suffix}")
            elif step_type == "Choice":
                current_def = step_data.get("Default", "")
                opts = [o for o in keys if o != selected_step]
                def_idx = opts.index(current_def) if current_def in opts else 0
                if opts: step_data["Default"] = st.selectbox("Else (Default Path)", opts, index=def_idx, key=f"sel_choice_def{key_suffix}_{len(opts)}")
                choices = step_data.get("Choices", [])
                for i, choice in enumerate(choices):
                    with st.expander(f"Rule #{i+1}: {choice.get('Variable','?')}", expanded=False):
                        choice["Variable"] = st.text_input("Var", value=choice.get("Variable", "$.input..."), key=f"c_var_{i}{key_suffix}")
                        ops = ["StringEquals", "NumericEquals", "BooleanEquals"]
                        curr_op = next((op for op in ops if op in choice), "StringEquals")
                        new_op = st.selectbox("Op", ops, index=ops.index(curr_op), key=f"c_op_{i}{key_suffix}")
                        val = choice.get(curr_op, "")
                        choice[new_op] = st.text_input("Val", value=str(val), key=f"c_val_{i}{key_suffix}")
                        if new_op != curr_op and curr_op in choice: del choice[curr_op]
                        curr_next = choice.get("Next", "")
                        n_idx = opts.index(curr_next) if curr_next in opts else 0
                        choice["Next"] = st.selectbox("Go To", opts, index=n_idx, key=f"c_next_{i}{key_suffix}")
                        if st.button("🗑️", key=f"del_rule_{i}{key_suffix}"): choices.pop(i); safe_rerun()
                if st.button("➕ Add Rule", key=f"btn_add_rule{key_suffix}"):
                    if opts: 
                        if "Choices" not in step_data: step_data["Choices"] = []
                        step_data["Choices"].append({"Variable": "$.input", "StringEquals": "", "Next": opts[0]})
                        safe_rerun()
            elif step_type == "Pass":
                new_res = st.text_area("Result JSON", value=json.dumps(step_data.get("Result", {}), indent=2), key=f"inp_pass_res{key_suffix}")
                try: step_data["Result"] = json.loads(new_res)
                except: st.error("Invalid JSON")
            elif step_type == "Fail":
                step_data["Error"] = st.text_input("Error Code", value=step_data.get("Error", "Error"), key=f"inp_fail_err{key_suffix}")
                step_data["Cause"] = st.text_input("Cause", value=step_data.get("Cause", ""), key=f"inp_fail_cause{key_suffix}")

            st.write("---")
            col_del, col_save = st.columns(2)
            with col_del:
                if st.button("🗑️ Delete Step", type="secondary", key=f"btn_del_step{key_suffix}"):
                    del st.session_state["flow_json"]["States"][selected_step]
                    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                    safe_rerun()
            with col_save:
                if st.button("💾 Apply Changes", type="primary", key=f"btn_apply_visual{key_suffix}"):
                    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                    st.success("Saved!")
                    safe_rerun()

    with c2:
        st.markdown("### Visual Flow")
        render_flow_graph(curr)

# --- TAB 4: DEPLOY ---
with t_dep:
    if not st.session_state.get("is_connected"): st.warning("Connect first")
    else:
        st.markdown("### 🚀 Deploy to ZIS")
        sub = st.session_state.get("zd_subdomain", "sub")
        valid_int = f"zis_playground_{sub.lower().strip()}"
        
        with st.container(border=True):
            st.info(f"Target Integration: **{valid_int}**")
            bun_name = st.text_input("Bundle Name", value=st.session_state.get("current_bundle_name", "my_new_flow"))
            
            if st.button("Deploy Bundle", type="primary"):
                with st.status("Deploying...", expanded=True) as status:
                    try:
                        requests.post(f"{get_base_url()}/integrations", auth=get_auth(), json={"name": valid_int, "display_name": valid_int}, headers={"Content-Type": "application/json"})
                        status.write("Integration checked.")
                        
                        safe_bun = bun_name.lower().replace("-", "_").replace(" ", "")
                        res_name = f"{safe_bun}_flow"
                        clean_def = clean_flow_logic(st.session_state["flow_json"])
                        
                        payload = {
                            "zis_template_version": "2019-10-14", "name": safe_bun,
                            "resources": {res_name: {"type": "ZIS::Flow", "properties": {"name": res_name, "definition": clean_def}}}
                        }
                        
                        r = requests.post(f"{get_base_url()}/{valid_int}/bundles", auth=get_auth(), json=payload, headers={"Content-Type": "application/json"})
                        
                        if r.status_code in [200, 201]:
                            st.balloons()
                            status.update(label="Deployment Successful!", state="complete")
                            st.success(f"Deployed **{safe_bun}**")
                        else:
                            status.update(label="Deployment Failed", state="error")
                            st.error(r.text)
                    except Exception as e: st.error(str(e))

# --- TAB 5: DEBUG ---
with t_deb:
    col_in, col_out = st.columns([1, 1])
    with col_in:
        st.subheader("Input")
        inp = st.text_area("JSON Input", '{"ticket": {"id": 123}}', height=300)
        if st.button("▶️ Run Simulation", type="primary"):
            eng = ZISFlowEngine(st.session_state["flow_json"], json.loads(inp), {}, {})
            logs, ctx, path = eng.run()
            st.session_state["debug_res"] = (logs, ctx, path)
    
    with col_out:
        st.subheader("Output")
        if "debug_res" in st.session_state:
            logs, ctx, path = st.session_state["debug_res"]
            with st.expander("Logs", expanded=True):
                for l in logs: st.text(l)
            with st.expander("Context"): st.json(ctx)
            st.caption("Visual Trace:")
            render_flow_graph(st.session_state["flow_json"], path)