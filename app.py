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

def force_refresh():
    if hasattr(st, "rerun"):
        st.rerun()
    else:
        st.experimental_rerun()

# [HELPER] Remove Comments for JSON parsing
def remove_comments(json_str):
    pattern = r'("[^"\\]*(?:\\.[^"\\]*)*")|(/\*[\s\S]*?\*/)|(//.*)'
    def replace(match):
        if match.group(1): return match.group(1) 
        return ""
    try:
        return re.sub(pattern, replace, json_str)
    except:
        return json_str

# [FIXED] Robust Key Reader (Case Insensitive)
# This prevents the UI from thinking data is missing if keys are lowercase
def get_zis_key(data, key, default=None):
    if not isinstance(data, dict): return default
    # Try exact match first (PascalCase)
    if key in data: return data[key]
    # Try lowercase match (camelCase)
    lower_key = key.lower()
    for k, v in data.items():
        if k.lower() == lower_key:
            return v
    return default

# [FIXED] Normalize Keys to PascalCase (Comprehensive ZIS Support)
def normalize_zis_keys(obj):
    if isinstance(obj, dict):
        new_obj = {}
        # Complete list of ZIS / ASL keys that must be PascalCase
        zis_keys = {
            # Structure
            "startat": "StartAt", "states": "States", "type": "Type",
            "next": "Next", "default": "Default", "choices": "Choices",
            "parameters": "Parameters", "actionname": "ActionName",
            "end": "End", "comment": "Comment", "definition": "Definition",
            
            # Paths
            "inputpath": "InputPath", "outputpath": "OutputPath", 
            "resultpath": "ResultPath", "result": "Result", "itemspath": "ItemsPath",
            
            # Error Handling & Retry
            "cause": "Cause", "error": "Error", "catch": "Catch", 
            "retry": "Retry", "errorequals": "ErrorEquals",
            "intervalseconds": "IntervalSeconds", "maxattempts": "MaxAttempts", 
            "backoffrate": "BackoffRate",

            # Choice Operators
            "variable": "Variable", 
            "stringequals": "StringEquals", "stringlessthan": "StringLessThan",
            "stringgreaterthan": "StringGreaterThan", "stringgreaterthanequals": "StringGreaterThanEquals",
            "stringlessthanequals": "StringLessThanEquals", "stringmatches": "StringMatches",
            "numericequals": "NumericEquals", "numericlessthan": "NumericLessThan",
            "numericgreaterthan": "NumericGreaterThan", "numericgreaterthanequals": "NumericGreaterThanEquals",
            "numericlessthanequals": "NumericLessThanEquals",
            "booleanequals": "BooleanEquals",
            "timestampgreaterthan": "TimestampGreaterThan", "timestamplessthan": "TimestampLessThan",
            "timestampgreaterthanequals": "TimestampGreaterThanEquals", "timestamplessthanequals": "TimestampLessThanEquals",
            "ispresent": "IsPresent", "isnull": "IsNull"
        }
        for k, v in obj.items():
            lower_k = k.lower()
            # If known ZIS key, use PascalCase; else keep original (e.g. API param keys)
            final_key = zis_keys.get(lower_k, k) 
            new_obj[final_key] = normalize_zis_keys(v) 
        return new_obj
    elif isinstance(obj, list):
        return [normalize_zis_keys(item) for item in obj]
    else:
        return obj

def clean_flow_logic(flow_data):
    if not isinstance(flow_data, dict): return flow_data
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

st.markdown("""
<style>
    [data-testid="stSidebar"] { display: none; }
    [data-testid="collapsedControl"] { display: none; }
    header {visibility: hidden;}
    .block-container { padding-top: 1rem; padding-bottom: 2rem; }
</style>
""", unsafe_allow_html=True)

if "flow_json" not in st.session_state:
    st.session_state["flow_json"] = {"StartAt": "StartStep", "States": {"StartStep": {"Type": "Pass", "End": True}}}
if "editor_key" not in st.session_state: st.session_state["editor_key"] = 0 
if "editor_content" not in st.session_state:
    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)

for key in ["zd_subdomain", "zd_email", "zd_token"]:
    if key not in st.session_state: st.session_state[key] = ""

# ==========================================
# 2. LOGIC ENGINE (Internal Version)
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
            if path == "$": return data
            matches = parse(path.replace("$.", "")).find(data)
            return matches[0].value if matches else None
        except: return None
        
    def set_nested_value(self, path, value):
        """Fixes root overwrite bug"""
        if not path or not path.startswith("$."): return
        keys = path.replace("$.", "").split(".")
        current = self.context
        for key in keys[:-1]:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value

    def interpolate(self, text):
        if not isinstance(text, str): return text
        for ph in re.findall(r'\{\{(.*?)\}\}', text):
            val = self.resolve_path(ph, self.context)
            text = text.replace(f"{{{{{ph}}}}}", str(val))
        return text

    def run_action(self, state_name, state_def):
        # [FIX] Use get_zis_key for safe reading
        action_name = get_zis_key(state_def, "ActionName", "Unknown")
        params = {}
        # [FIX] Read parameters safely
        raw_params = get_zis_key(state_def, "Parameters", {})
        
        for k, v in raw_params.items():
            key = k[:-2] if k.endswith(".$") else k
            val = self.resolve_path(v, self.context) if k.endswith(".$") else self.interpolate(v)
            params[key] = val

        self.log(state_name, f"Action: {action_name}", "RUNNING")
        url = params.get("url", "")
        method = params.get("method", "GET")
        
        if url:
            try:
                resp = requests.request(method, url, json=params.get("body"))
                code = resp.status_code
                if code >= 400: self.log(state_name, f"API {code}: {resp.text[:50]}...", "ERROR")
                else: self.log(state_name, f"API {code}", "SUCCESS")
                return resp.json() if resp.content else {}
            except Exception as e:
                self.log(state_name, f"Error: {e}", "ERROR")
                return {"error": str(e)}
        else:
            self.log(state_name, "Mock Mode (No URL)", "WARNING")
            return {"mock": True, "params": params}

    def run(self):
        flow_def = self.flow.get("definition", self.flow)
        
        # [FIX] Robust reading of StartAt and States
        curr = get_zis_key(flow_def, "StartAt")
        states = get_zis_key(flow_def, "States", {})
        
        self.log("START", f"Flow: {self.context.get('flow_name', 'Local')}")
        steps = 0
        while curr and steps < 50:
            steps += 1
            self.visited_states.append(curr)
            state = states.get(curr)
            if not state: break
            
            # [FIX] Robust reading of Type
            sType = get_zis_key(state, "Type")
            
            # [FIX] Robust reading of Next and ResultPath
            next_step = get_zis_key(state, "Next")
            result_path = get_zis_key(state, "ResultPath")
            
            if sType == "Action":
                res = self.run_action(curr, state)
                if result_path: self.set_nested_value(result_path, res)
                curr = next_step
            elif sType == "Choice":
                curr = get_zis_key(state, "Default")
                matched = False
                choices = get_zis_key(state, "Choices", [])
                for rule in choices:
                    var_path = get_zis_key(rule, "Variable")
                    val = self.resolve_path(var_path, self.context)
                    
                    str_eq = get_zis_key(rule, "StringEquals")
                    bool_eq = get_zis_key(rule, "BooleanEquals")
                    rule_next = get_zis_key(rule, "Next")
                    
                    if str_eq is not None and str(str_eq) == str(val):
                        curr = rule_next; matched = True; break
                    if bool_eq is not None and bool(bool_eq) == bool(val):
                        curr = rule_next; matched = True; break
                
            elif sType == "Pass":
                res_val = get_zis_key(state, "Result")
                if res_val is not None and result_path:
                    self.set_nested_value(result_path, res_val)
                curr = next_step
            elif sType == "Wait":
                sec = get_zis_key(state, "Seconds", 1)
                time.sleep(float(sec))
                curr = next_step
            elif sType in ["Succeed", "Fail"]: break
            
            if get_zis_key(state, "End"): break
            
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
        return (True, "Active") if r.status_code == 200 else (False, f"Error {r.status_code}")
    except Exception as e: return False, f"{str(e)}"

def render_flow_graph(flow_def, highlight_path=None, selected_step=None):
    if not HAS_GRAPHVIZ: return st.warning("Graphviz missing")
    try:
        dot = graphviz.Digraph(comment='ZIS Flow')
        dot.attr(rankdir='TB', splines='ortho', bgcolor='transparent')
        dot.attr('node', shape='box', style='rounded,filled', fontcolor='black', fontname='Arial', fontsize='12')
        dot.attr('edge', color='#888888') 
        
        visited = set(highlight_path) if highlight_path else set()
        
        # [FIX] Robust reading
        start = get_zis_key(flow_def, "StartAt")
        
        dot.node("START", "Start", shape="circle", fillcolor="#4CAF50", fontcolor="white", width="0.8", style="filled")
        if start: dot.edge("START", start)

        states = get_zis_key(flow_def, "States", {})
        for k, v in states.items():
            fill = "#e0e0e0" 
            pen = "1"
            if k in visited:
                fill = "#C8E6C9" 
                pen = "2"
                if highlight_path and k == highlight_path[-1]: fill = "#81C784"
            
            if selected_step and k == selected_step:
                fill = "#FFF59D" 
                pen = "3"

            sType = get_zis_key(v, "Type", "Unknown")
            dot.node(k, f"{k}\n({sType})", fillcolor=fill, penwidth=pen)
            
            next_step = get_zis_key(v, "Next")
            if next_step: dot.edge(k, next_step)
            
            default_step = get_zis_key(v, "Default")
            if default_step: dot.edge(k, default_step, label="Default")
            
            choices = get_zis_key(v, "Choices", [])
            for c in choices:
                c_next = get_zis_key(c, "Next")
                if c_next: dot.edge(k, c_next, label="If Match")
            
            if get_zis_key(v, "End"): 
                dot.node("END", "End", shape="doublecircle", fillcolor="#333333", fontcolor="white", width="0.6", style="filled")
                dot.edge(k, "END")
        st.graphviz_chart(dot) 
    except: pass

# ==========================================
# 4. MAIN WORKSPACE
# ==========================================
st.title("ZIS Studio")

t_set, t_imp, t_code, t_vis, t_dep, t_deb = st.tabs([
    "⚙️ Settings", "📥 Import", "📝 Code Editor", "🎨 Visual Designer", "🚀 Deploy", "🐞 Debugger"
])

# --- TAB 1: SETTINGS ---
with t_set:
    st.markdown("### 🔑 Zendesk Credentials")
    col_creds, col_info = st.columns([1, 1])
    with col_creds:
        with st.container(border=True):
            st.text_input("Subdomain", key="zd_subdomain", help="Just the subdomain")
            st.text_input("Email", key="zd_email")
            st.text_input("API Token", key="zd_token", type="password")
            st.write("") 
            if st.button("Test Connection", type="primary", use_container_width=True):
                ok, msg = test_connection()
                if ok: 
                    st.session_state["is_connected"] = True
                    st.toast(msg, icon="✅") 
                else: 
                    st.toast(msg, icon="❌")
    with col_info:
        if st.session_state.get("is_connected"):
            st.success(f"✅ Connected to: **{st.session_state.zd_subdomain}.zendesk.com**")

# --- TAB 2: IMPORT ---
with t_imp:
    st.markdown("### 🔎 Find Existing Flows")
    if not st.session_state.get("is_connected"):
        st.warning("Please configure your credentials in the '⚙️ Settings' tab first.")
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
                                results.append({"int": int_name, "bun": b["name"], "uuid": b.get("uuid", "")})
                        time.sleep(0.05)
                    st.session_state["scan_results"] = results
                    status_text.empty(); progress_bar.empty()
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
                                    raw_def = clean_flow_logic(v["properties"]["definition"])
                                    norm_def = normalize_zis_keys(raw_def)
                                    st.session_state["flow_json"] = norm_def
                                    st.session_state["editor_content"] = json.dumps(norm_def, indent=2)
                                    st.session_state["current_bundle_name"] = item['bun']
                                    st.session_state["editor_key"] += 1 
                                    st.toast("Flow Loaded Successfully!", icon="🎉")
                                    found = True
                                    time.sleep(0.5); force_refresh()
                                    break
                            if not found: st.warning("No Flow resource found.")
                        else: st.error("Fetch failed. Please check permissions.")

# --- TAB 3: CODE ---
with t_code:
    dynamic_key = f"code_editor_{st.session_state['editor_key']}"
    if HAS_EDITOR:
        btn_settings = [{
            "name": "Save", "feather": "Save", "primary": True, "hasText": True, "alwaysOn": True, 
            "commands": ["submit"], "style": {"top": "0.46rem", "right": "0.4rem"} 
        }]
        editor_options = {"showGutter": True, "showLineNumbers": True, "wrap": True, "fontSize": 14, "fontFamily": "monospace"}
        
        resp = code_editor(st.session_state.get("editor_content", ""), lang="json", height=500, options=editor_options, buttons=btn_settings, key=dynamic_key)
        
        if resp and resp.get("text"): st.session_state["editor_content"] = resp["text"]

        if resp and resp.get("type") == "submit":
            try:
                latest_text = resp.get("text", "")
                clean_text = remove_comments(latest_text)
                js = json.loads(clean_text)
                
                if "resources" in js:
                    for res_k, res_v in js["resources"].items():
                        if res_v.get("type") == "ZIS::Flow":
                            js = res_v["properties"]["definition"]
                            st.toast(f"📦 Extracted Flow: {res_k}", icon="✂️")
                            break

                clean_js = clean_flow_logic(js.get("definition", js))
                norm_js = normalize_zis_keys(clean_js)
                
                formatted_json = json.dumps(norm_js, indent=2, sort_keys=False)
                
                if formatted_json != st.session_state.get("editor_content"):
                    st.session_state["editor_content"] = formatted_json
                    st.session_state["editor_key"] += 1
                
                st.session_state["flow_json"] = norm_js
                st.toast("Code Validated, Normalized & Saved!", icon="✅")
                if norm_js != st.session_state.get("flow_json"):
                    force_refresh()
                    
            except json.JSONDecodeError as e: st.error(f"❌ Save Failed: Invalid JSON.\n\nError: {e}")
            except Exception as e: st.error(f"❌ Error: {e}")
    else:
        txt = st.text_area("JSON", st.session_state.get("editor_content", ""), height=500, key=dynamic_key)
        if st.button("Save", key="save_text"):
            try:
                clean_text = remove_comments(txt)
                js = json.loads(clean_text)
                if "resources" in js:
                    for res_k, res_v in js["resources"].items():
                        if res_v.get("type") == "ZIS::Flow":
                            js = res_v["properties"]["definition"]
                            break
                clean_js = clean_flow_logic(js.get("definition", js))
                norm_js = normalize_zis_keys(clean_js)
                
                st.session_state["flow_json"] = norm_js
                st.session_state["editor_content"] = json.dumps(norm_js, indent=2)
                st.toast("Saved & Normalized", icon="💾")
                force_refresh()
            except: st.error("Invalid JSON")

# --- TAB 4: DESIGNER ---
with t_vis:
    c1, c2 = st.columns([1, 2])
    # [FIX] Robust key reading for the main flow object
    curr = st.session_state["flow_json"]
    states = get_zis_key(curr, "States", {})
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
                    elif new_step_type == "Choice": new_def["Choices"] = []; new_def["Default"] = new_step_name 
                    elif new_step_type == "Fail": new_def["Error"] = "ErrorName"; new_def["Cause"] = "Cause"
                    elif new_step_type == "Action": new_def["ActionName"] = "zis:common:action:fetch"; new_def["Parameters"] = {}
                    else: new_def["End"] = True
                    
                    st.session_state["flow_json"]["States"][new_step_name] = new_def
                    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                    st.success(f"Created {new_step_name}")
                    force_refresh()
                else: st.error("Name required or already exists.")

        st.divider()
        if selected_step and selected_step != "(Select a Step)" and selected_step in states:
            step_data = states[selected_step]
            # [FIX] Case Insensitive Read
            step_type = get_zis_key(step_data, "Type")
            st.markdown(f"### ⚙️ {selected_step} `[{step_type}]`")
            
            key_suffix = f"_{selected_step}"
            is_terminal = step_type in ["Succeed", "Fail", "Choice"] 
            
            if not is_terminal:
                is_end_val = get_zis_key(step_data, "End", False)
                is_end = st.checkbox("End Flow?", value=is_end_val, key=f"chk_is_end{key_suffix}")
                
                if is_end: 
                    step_data["End"] = True
                    # Remove Next/next if present
                    if "Next" in step_data: del step_data["Next"]
                    if "next" in step_data: del step_data["next"]
                else:
                    if "End" in step_data: del step_data["End"]
                    if "end" in step_data: del step_data["end"]
                    
                    # [FIX] Read current next carefully
                    current_next = get_zis_key(step_data, "Next", "")
                    next_options = [opt for opt in keys if opt != selected_step]
                    
                    if current_next not in next_options:
                        final_options = ["(Select a Step)"] + next_options
                        idx = 0
                    else:
                        final_options = next_options
                        idx = next_options.index(current_next)

                    if final_options:
                        selected_val = st.selectbox("Go to Next", final_options, index=idx, key=f"sel_next_step{key_suffix}_{len(final_options)}")
                        if selected_val != "(Select a Step)":
                            step_data["Next"] = selected_val
                    else: st.warning("Create another step to link to.")

            if step_type == "Action":
                curr_act = get_zis_key(step_data, "ActionName", "")
                step_data["ActionName"] = st.text_input("Action Name", value=curr_act, key=f"inp_act_name{key_suffix}")
                
                # [FIX] Read parameters carefully
                curr_params = get_zis_key(step_data, "Parameters", {})
                current_params_str = json.dumps(curr_params, indent=2)
                
                new_params = st.text_area("Parameters JSON", value=current_params_str, height=150, key=f"inp_act_params{key_suffix}")
                try: step_data["Parameters"] = json.loads(new_params)
                except: st.error("Invalid JSON")
                
            elif step_type == "Wait":
                curr_sec = get_zis_key(step_data, "Seconds", 5)
                step_data["Seconds"] = st.number_input("Wait (Sec)", min_value=1, value=int(curr_sec), key=f"inp_wait_sec{key_suffix}")
            
            elif step_type == "Choice":
                current_def = get_zis_key(step_data, "Default", "")
                opts = [o for o in keys if o != selected_step]
                
                if current_def not in opts:
                    def_options = ["(Select a Step)"] + opts
                    d_idx = 0
                else:
                    def_options = opts
                    d_idx = opts.index(current_def)
                
                if opts: 
                    sel_def = st.selectbox("Else (Default Path)", def_options, index=d_idx, key=f"sel_choice_def{key_suffix}_{len(opts)}")
                    if sel_def != "(Select a Step)":
                         step_data["Default"] = sel_def
                
                choices = get_zis_key(step_data, "Choices", [])
                # If reading choices failed due to casing, ensure we initialize it
                if "Choices" not in step_data and "choices" in step_data:
                    step_data["Choices"] = step_data.pop("choices")
                    choices = step_data["Choices"]
                
                for i, choice in enumerate(choices):
                    with st.expander(f"Rule #{i+1}", expanded=False):
                        # [FIX] Safe reads inside choice
                        curr_var = get_zis_key(choice, "Variable", "$.input...")
                        curr_val = get_zis_key(choice, "StringEquals", "")
                        curr_nxt = get_zis_key(choice, "Next", "")

                        choice["Variable"] = st.text_input("Variable", value=curr_var, key=f"c_var_{i}{key_suffix}")
                        choice["StringEquals"] = st.text_input("Equals (String)", value=str(curr_val), key=f"c_val_{i}{key_suffix}")
                        
                        if curr_nxt not in opts:
                            c_options = ["(Select a Step)"] + opts
                            c_idx = 0
                        else:
                            c_options = opts
                            c_idx = opts.index(curr_nxt)
                        
                        sel_choice_next = st.selectbox("Go To", c_options, index=c_idx, key=f"c_next_{i}{key_suffix}")
                        if sel_choice_next != "(Select a Step)":
                            choice["Next"] = sel_choice_next
                        
                        if st.button("🗑️", key=f"del_rule_{i}{key_suffix}"): choices.pop(i); force_refresh()

                if st.button("➕ Add Rule", key=f"btn_add_rule{key_suffix}"):
                    if opts: 
                        if "Choices" not in step_data: step_data["Choices"] = []
                        step_data["Choices"].append({"Variable": "$.input", "StringEquals": "", "Next": opts[0]})
                        force_refresh()

            st.write("---")
            col_del, col_save = st.columns(2)
            with col_del:
                if st.button("🗑️ Delete Step", type="secondary", key=f"btn_del_step{key_suffix}"):
                    del st.session_state["flow_json"]["States"][selected_step]
                    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                    force_refresh()
            with col_save:
                if st.button("💾 Apply Changes", type="primary", key=f"btn_apply_visual{key_suffix}"):
                    st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                    st.success("Saved!")
                    force_refresh()

    with c2:
        st.markdown("### Visual Flow")
        render_flow_graph(curr, selected_step=selected_step if selected_step != "(Select a Step)" else None)

# --- TAB 5: DEPLOY ---
with t_dep:
    if not st.session_state.get("is_connected"): st.warning("Please configure your credentials in the '⚙️ Settings' tab first.")
    else:
        st.markdown("### 🚀 Deploy to ZIS")
        sub = st.session_state.get("zd_subdomain", "sub")
        default_int = f"zis_playground_{sub.lower().strip()}"
        with st.container(border=True):
            raw_int_name = st.text_input("Target Integration Name", value=default_int, help="Keep the default for testing, or change it for production deployment.")
            target_int = raw_int_name.lower().strip().replace(" ", "_")
            bun_name = st.text_input("Bundle Name", value=st.session_state.get("current_bundle_name", "my_new_flow"))
            if st.button("Deploy Bundle", type="primary"):
                with st.status("Deploying...", expanded=True) as status:
                    try:
                        status.write(f"Checking integration: {target_int}...")
                        requests.post(f"{get_base_url()}/integrations", auth=get_auth(), json={"name": target_int, "display_name": target_int}, headers={"Content-Type": "application/json"})
                        
                        safe_bun = bun_name.lower().strip().replace("-", "_").replace(" ", "")
                        res_name = f"{safe_bun}_flow"
                        
                        clean_def = clean_flow_logic(st.session_state["flow_json"])
                        norm_def = normalize_zis_keys(clean_def)
                        
                        payload = {"zis_template_version": "2019-10-14", "name": safe_bun, "resources": {res_name: {"type": "ZIS::Flow", "properties": {"name": res_name, "definition": norm_def}}}}
                        r = requests.post(f"{get_base_url()}/{target_int}/bundles", auth=get_auth(), json=payload, headers={"Content-Type": "application/json"})
                        if r.status_code in [200, 201]:
                            st.balloons(); status.update(label="Deployment Successful!", state="complete"); st.success(f"Deployed **{safe_bun}** to integration **{target_int}**")
                        else:
                            status.update(label="Deployment Failed", state="error"); st.error(r.text)
                    except Exception as e: st.error(str(e))

# --- TAB 6: DEBUG ---
with t_deb:
    col_input, col_graph = st.columns([1, 1])
    with col_input:
        st.markdown("### Input")
        inp = st.text_area("JSON Input", '{"ticket": {"id": 123}}', height=200, key="debug_input")
        if st.button("▶️ Run Simulation", type="primary", key="btn_run_debug"):
            eng = ZISFlowEngine(normalize_zis_keys(st.session_state["flow_json"]), json.loads(inp), {}, {})
            logs, ctx, path = eng.run()
            st.session_state["debug_res"] = (logs, ctx, path)
        st.divider()
        if "debug_res" in st.session_state:
            st.markdown("### Output")
            logs, ctx, path = st.session_state["debug_res"]
            with st.expander("Logs", expanded=True):
                for l in logs:
                    if "(ERROR)" in l: st.error(l, icon="❌")
                    elif "(SUCCESS)" in l: st.success(l, icon="✅")
                    elif "(WARNING)" in l: st.warning(l, icon="⚠️")
                    else: st.text(l)
            with st.expander("Context", expanded=True): st.json(ctx)
    with col_graph:
        st.markdown("### Visual Trace")
        current_path = st.session_state["debug_res"][2] if "debug_res" in st.session_state else None
        render_flow_graph(st.session_state["flow_json"], current_path)