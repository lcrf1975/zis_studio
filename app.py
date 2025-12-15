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

# [HELPER] Robust Key Reader (Case Insensitive)
def get_zis_key(data, key, default=None):
    if not isinstance(data, dict): return default
    # Priority 1: Exact Match
    if key in data: return data[key]
    # Priority 2: Case Insensitive Match
    lower_key = key.lower()
    for k, v in data.items():
        if k.lower() == lower_key:
            return v
    return default

# [HELPER] Smart Index Finder (Prevents Jumping to Index 0)
def find_best_match_index(options, target_value):
    if not target_value: return -1
    
    # 1. Exact Match
    if target_value in options:
        return options.index(target_value)
    
    # 2. Case Insensitive Match
    lower_target = str(target_value).lower().strip()
    for i, opt in enumerate(options):
        if str(opt).lower().strip() == lower_target:
            return i
            
    # 3. No match found
    return -1

# [HELPER] Normalize & Clean Logic
def normalize_zis_keys(obj):
    if isinstance(obj, dict):
        new_obj = {}
        zis_keys = {
            "startat": "StartAt", "states": "States", "type": "Type",
            "next": "Next", "default": "Default", "choices": "Choices",
            "parameters": "Parameters", "actionname": "ActionName",
            "end": "End", "comment": "Comment", "definition": "Definition",
            "inputpath": "InputPath", "outputpath": "OutputPath", 
            "resultpath": "ResultPath", "result": "Result", "itemspath": "ItemsPath",
            "cause": "Cause", "error": "Error", "catch": "Catch", 
            "retry": "Retry", "errorequals": "ErrorEquals",
            "variable": "Variable", "stringequals": "StringEquals", 
            "booleanequals": "BooleanEquals", "numericequals": "NumericEquals",
            "numericgreaterthan": "NumericGreaterThan", 
            "numericgreaterthanequals": "NumericGreaterThanEquals",
            "numericlessthan": "NumericLessThan", 
            "numericlessthanequals": "NumericLessThanEquals",
            "ispresent": "IsPresent", "isnull": "IsNull", "seconds": "Seconds"
        }
        for k, v in obj.items():
            lower_k = k.lower()
            # If we have a known ZIS key, force PascalCase
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

# [NEW] Sanitize Step Data (Run before editing)
# Merges "next" and "Next" to avoid conflicts that confuse the UI
def sanitize_step(step_data):
    keys_to_fix = {
        "next": "Next", "actionname": "ActionName", 
        "parameters": "Parameters", "default": "Default", 
        "choices": "Choices", "type": "Type", "end": "End",
        "resultpath": "ResultPath", "seconds": "Seconds"
    }
    
    # Snapshot of keys to avoid runtime dict change errors
    existing_keys = list(step_data.keys())
    
    for k in existing_keys:
        k_lower = k.lower()
        if k_lower in keys_to_fix:
            target = keys_to_fix[k_lower]
            # If we have a lowercase key (e.g. 'next')
            if k != target:
                val = step_data[k]
                # If target ('Next') is missing, move value there
                if target not in step_data:
                    step_data[target] = val
                # Delete the old lowercase key to prevent duplicate truth
                del step_data[k]

# [CRITICAL] Sync Function: Ensures flow_json matches editor_content
def try_sync_from_editor(force_ui_update=False):
    """
    Attempts to parse the current editor string content into the flow_json object.
    Returns (True, parsed_json) if successful, (False, None) if invalid JSON.
    """
    content = st.session_state.get("editor_content", "")
    if not content:
        return False, None
    
    try:
        js = json.loads(remove_comments(content))
        
        # Handle ZIS Bundle wrapper structure if present
        if "resources" in js:
            for v in js["resources"].values():
                if v.get("type") == "ZIS::Flow": 
                    js = v["properties"]["definition"]
                    break
        
        norm_js = normalize_zis_keys(clean_flow_logic(js))
        st.session_state["flow_json"] = norm_js
        
        if force_ui_update:
            st.session_state["editor_content"] = json.dumps(norm_js, indent=2)
            st.session_state["editor_key"] += 1
            
        return True, norm_js
    except Exception as e:
        return False, None

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
# 2. LOGIC ENGINE (Moved to zis_engine.py but kept simple ref here for debug tab import if needed)
# ==========================================
# (Importing from file in actual usage, but defining class here for standalone run)
from zis_engine import ZISFlowEngine

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
            st.text_input("Subdomain", key="zd_subdomain")
            st.text_input("Email", key="zd_email")
            st.text_input("API Token", key="zd_token", type="password")
            if st.button("Test Connection"):
                ok, msg = test_connection()
                if ok: st.session_state["is_connected"] = True; st.toast(msg, icon="✅") 
                else: st.toast(msg, icon="❌")
    with col_info:
        if st.session_state.get("is_connected"):
            st.success(f"✅ Connected to: **{st.session_state.zd_subdomain}.zendesk.com**")

# --- TAB 2: IMPORT ---
with t_imp:
    st.markdown("### 🔎 Find Existing Flows")
    if not st.session_state.get("is_connected"):
        st.warning("Please configure your credentials in the '⚙️ Settings' tab first.")
    else:
        if st.button("🚀 Start Deep Scan"):
            results = []
            status_text = st.empty()
            try:
                status_text.text("Fetching...")
                resp = requests.get(f"{get_base_url()}/integrations", auth=get_auth())
                if resp.status_code == 200:
                    ints = resp.json().get("integrations", [])
                    for idx, int_obj in enumerate(ints):
                        int_name = int_obj["name"]
                        status_text.text(f"Scanning {int_name}...")
                        b_resp = requests.get(f"{get_base_url()}/{int_name}/bundles", auth=get_auth())
                        if b_resp.status_code == 200:
                            for b in b_resp.json().get("bundles", []):
                                results.append({"int": int_name, "bun": b["name"], "uuid": b.get("uuid", "")})
                        time.sleep(0.05)
                    st.session_state["scan_results"] = results
                    status_text.empty()
                    if results: st.success(f"Found {len(results)} bundles.")
                    else: st.warning("No bundles found.")
                else: st.error("Failed to fetch.")
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
                                    st.toast("Flow Loaded!", icon="🎉")
                                    found = True
                                    time.sleep(0.5); force_refresh()
                                    break
                            if not found: st.warning("No Flow resource found.")
                        else: st.error("Fetch failed.")

# --- TAB 3: CODE ---
with t_code:
    dynamic_key = f"code_editor_{st.session_state['editor_key']}"
    if HAS_EDITOR:
        resp = code_editor(st.session_state.get("editor_content", ""), lang="json", height=500, key=dynamic_key)
        
        # [FIX] Enhanced Sync Logic
        if resp and resp.get("text"):
            st.session_state["editor_content"] = resp["text"]
            is_valid, _ = try_sync_from_editor(force_ui_update=False)

            if resp.get("type") == "submit":
                if is_valid:
                    try_sync_from_editor(force_ui_update=True)
                    st.toast("Saved!", icon="✅")
                    force_refresh()
                else:
                    st.error("Invalid JSON")

# --- TAB 4: VISUAL DESIGNER ---
with t_vis:
    sync_ok, _ = try_sync_from_editor(force_ui_update=False)
    
    if not sync_ok:
        st.error("⚠️ **Syntax Error:** The code in the 'Code Editor' tab is invalid JSON. Please fix it before using the Visual Designer.")
    else:
        c1, c2 = st.columns([1, 2])
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
            
            with st.expander("➕ Add New Step"):
                new_step_name = st.text_input("New Step Name", key="inp_new_name")
                new_step_type = st.selectbox("Type", ["Action", "Choice", "Wait", "Pass", "Succeed", "Fail"], key="sel_new_type")
                if st.button("Create Step"):
                    if new_step_name and new_step_name not in states:
                        new_def = {"Type": new_step_type}
                        if new_step_type == "Pass": new_def["End"] = True
                        st.session_state["flow_json"]["States"][new_step_name] = new_def
                        st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                        force_refresh()

            st.divider()
            if selected_step and selected_step != "(Select a Step)" and selected_step in states:
                step_data = states[selected_step]
                sanitize_step(step_data)
                step_type = get_zis_key(step_data, "Type")
                st.markdown(f"### ⚙️ {selected_step} `[{step_type}]`")
                
                key_suffix = f"_{selected_step}"
                is_terminal = step_type in ["Succeed", "Fail", "Choice"] 
                
                if not is_terminal:
                    is_end_val = get_zis_key(step_data, "End", False)
                    is_end = st.checkbox("End Flow?", value=is_end_val, key=f"chk_is_end{key_suffix}")
                    
                    if is_end: 
                        step_data["End"] = True
                        if "Next" in step_data: del step_data["Next"]
                    else:
                        if "End" in step_data: del step_data["End"]
                        current_next = get_zis_key(step_data, "Next", "")
                        next_options = [opt for opt in keys if opt != selected_step]
                        idx = find_best_match_index(next_options, current_next)
                        final_options = ["(Select a Step)"] + next_options if idx == -1 else next_options
                        final_idx = 0 if idx == -1 else idx
                        
                        selected_val = st.selectbox("Go to Next", final_options, index=final_idx, key=f"sel_next_{selected_step}_{current_next}")
                        if selected_val != "(Select a Step)" and selected_val != current_next:
                            step_data["Next"] = selected_val

                if step_type == "Action":
                    curr_act = get_zis_key(step_data, "ActionName", "")
                    new_act = st.text_input("Action Name", value=curr_act, key=f"inp_act_name{key_suffix}")
                    if new_act != curr_act: step_data["ActionName"] = new_act
                    
                    curr_params = get_zis_key(step_data, "Parameters", {})
                    current_params_str = json.dumps(curr_params, indent=2)
                    new_params_str = st.text_area("Parameters JSON", value=current_params_str, height=150, key=f"inp_act_params{key_suffix}")
                    
                    if new_params_str != current_params_str:
                        try: step_data["Parameters"] = json.loads(new_params_str)
                        except: st.error("Invalid JSON")
                    
                elif step_type == "Choice":
                    current_def = get_zis_key(step_data, "Default", "")
                    opts = [o for o in keys if o != selected_step]
                    
                    d_idx = find_best_match_index(opts, current_def)
                    def_opts = ["(Select a Step)"] + opts if d_idx == -1 else opts
                    def_final_idx = 0 if d_idx == -1 else d_idx
                    
                    sel_def = st.selectbox("Else (Default Path)", def_opts, index=def_final_idx, key=f"sel_choice_def{key_suffix}")
                    if sel_def != "(Select a Step)" and sel_def != current_def:
                         step_data["Default"] = sel_def
                    
                    choices = get_zis_key(step_data, "Choices", [])
                    if "Choices" not in step_data and "choices" in step_data: step_data["Choices"] = step_data.pop("choices")
                    
                    # [UPDATE] Dynamic Operator Handling
                    possible_ops = [
                        "StringEquals", "BooleanEquals", "NumericEquals", 
                        "NumericGreaterThan", "NumericGreaterThanEquals", 
                        "NumericLessThan", "NumericLessThanEquals"
                    ]
                    
                    for i, choice in enumerate(choices):
                        with st.expander(f"Rule #{i+1}", expanded=False):
                            # 1. Detect Operator
                            current_op = "StringEquals" # Default
                            current_val = ""
                            
                            for op in possible_ops:
                                found = get_zis_key(choice, op)
                                if found is not None:
                                    current_op = op
                                    current_val = found
                                    break
                            
                            # 2. Variable Input
                            v_val = get_zis_key(choice, "Variable", "$.input...")
                            nv = st.text_input("Variable", value=v_val, key=f"c_var_{i}{key_suffix}")
                            if nv != v_val: choice["Variable"] = nv
                            
                            # 3. Operator & Value Input
                            col_op, col_val = st.columns([1, 1])
                            with col_op:
                                sel_op = st.selectbox("Condition", possible_ops, index=possible_ops.index(current_op), key=f"c_op_{i}{key_suffix}")
                            with col_val:
                                new_val_str = st.text_input("Value", value=str(current_val), key=f"c_val_{i}{key_suffix}")
                            
                            # 4. Save Logic (If changed)
                            if sel_op != current_op or new_val_str != str(current_val):
                                # Remove old operator
                                if current_op in choice: del choice[current_op]
                                if current_op.lower() in choice: del choice[current_op.lower()]
                                
                                # Convert new value
                                final_val = new_val_str
                                if "Numeric" in sel_op:
                                    try: 
                                        if "." in new_val_str: final_val = float(new_val_str)
                                        else: final_val = int(new_val_str)
                                    except: pass # Keep string if fail
                                elif "Boolean" in sel_op:
                                    final_val = (new_val_str.lower() == "true")
                                
                                choice[sel_op] = final_val

                            # 5. Next Step
                            n_val = get_zis_key(choice, "Next", "")
                            c_idx = find_best_match_index(opts, n_val)
                            c_opts = ["(Select a Step)"] + opts if c_idx == -1 else opts
                            c_final_idx = 0 if c_idx == -1 else c_idx
                            
                            sel_choice_next = st.selectbox("Then (Go To)", c_opts, index=c_final_idx, key=f"c_next_{i}{key_suffix}")
                            if sel_choice_next != "(Select a Step)" and sel_choice_next != n_val:
                                choice["Next"] = sel_choice_next
                            
                            if st.button("🗑️", key=f"del_rule_{i}{key_suffix}"): choices.pop(i); force_refresh()

                    if st.button("➕ Add Rule"):
                        if "Choices" not in step_data: step_data["Choices"] = []
                        step_data["Choices"].append({"Variable": "$.input", "StringEquals": "", "Next": opts[0] if opts else ""})
                        force_refresh()

                st.write("---")
                c_del, c_save = st.columns(2)
                with c_del:
                    if st.button("🗑️ Delete Step"):
                        del st.session_state["flow_json"]["States"][selected_step]
                        st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                        force_refresh()
                with c_save:
                    if st.button("💾 Apply Changes", type="primary"):
                        st.session_state["editor_content"] = json.dumps(st.session_state["flow_json"], indent=2)
                        st.success("Saved!"); force_refresh()

        with c2:
            st.markdown("### Visual Flow")
            render_flow_graph(curr, selected_step=selected_step if selected_step != "(Select a Step)" else None)

# --- TAB 5 & 6 (Deploy & Debug) ---
with t_dep:
    if not st.session_state.get("is_connected"): st.warning("Connect in Settings first.")
    else:
        st.markdown("### 🚀 Deploy")
        sub = st.session_state.get("zd_subdomain", "sub")
        default_int = f"zis_playground_{sub.lower().strip()}"
        with st.container(border=True):
            raw_int_name = st.text_input("Target Integration Name", value=default_int)
            target_int = raw_int_name.lower().strip().replace(" ", "_")
            bun_name = st.text_input("Bundle Name", value=st.session_state.get("current_bundle_name", "my_new_flow"))
            if st.button("Deploy Bundle", type="primary"):
                with st.status("Deploying...") as status:
                    try:
                        status.write("Creating integration...")
                        requests.post(f"{get_base_url()}/integrations", auth=get_auth(), json={"name": target_int, "display_name": target_int}, headers={"Content-Type": "application/json"})
                        
                        safe_bun = bun_name.lower().strip().replace("-", "_").replace(" ", "")
                        res_name = f"{safe_bun}_flow"
                        norm_def = normalize_zis_keys(clean_flow_logic(st.session_state["flow_json"]))
                        
                        payload = {"zis_template_version": "2019-10-14", "name": safe_bun, "resources": {res_name: {"type": "ZIS::Flow", "properties": {"name": res_name, "definition": norm_def}}}}
                        r = requests.post(f"{get_base_url()}/{target_int}/bundles", auth=get_auth(), json=payload, headers={"Content-Type": "application/json"})
                        if r.status_code in [200, 201]:
                            st.balloons(); status.update(label="Deployed!", state="complete"); st.success(f"Deployed {safe_bun} to {target_int}")
                        else:
                            status.update(label="Failed", state="error"); st.error(r.text)
                    except Exception as e: st.error(str(e))

with t_deb:
    col_input, col_graph = st.columns([1, 1])
    with col_input:
        st.markdown("### Input")
        inp = st.text_area("JSON Input", '{"ticket": {"id": 123}}', height=200, key="debug_input")
        if st.button("▶️ Run Simulation", type="primary"):
            eng = ZISFlowEngine(normalize_zis_keys(st.session_state["flow_json"]), json.loads(inp), {}, {})
            logs, ctx, path = eng.run()
            st.session_state["debug_res"] = (logs, ctx, path)
        st.divider()
        if "debug_res" in st.session_state:
            logs, ctx, path = st.session_state["debug_res"]
            with st.expander("Logs"):
                for l in logs: st.text(l)
            with st.expander("Context"): st.json(ctx)
    with col_graph:
        st.markdown("### Trace")
        current_path = st.session_state["debug_res"][2] if "debug_res" in st.session_state else None
        render_flow_graph(st.session_state["flow_json"], current_path)