import streamlit as st
import json
import requests
import time
import re
import base64
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

# [HELPER] Robust JSON Cleaner
def clean_json_string(json_str):
    if not isinstance(json_str, str): return ""
    json_str = json_str.strip()
    json_str = re.sub(r'^```[a-zA-Z]*\s*', '', json_str)
    json_str = re.sub(r'\s*```$', '', json_str)
    json_str = json_str.replace("\u00a0", " ")
    
    pattern = r'("[^"\\]*(?:\\.[^"\\]*)*")|(/\*[\s\S]*?\*/)|(//.*)'
    def replace(match):
        if match.group(1): return match.group(1) 
        return ""
    try:
        return re.sub(pattern, replace, json_str)
    except:
        return json_str

# [HELPER] Robust Key Reader
def get_zis_key(data, key, default=None):
    if not isinstance(data, dict): return default
    if key in data: return data[key]
    lower_key = key.lower()
    for k, v in data.items():
        if k.lower() == lower_key:
            return v
    return default

# [HELPER] Smart Index Finder
def find_best_match_index(options, target_value):
    if not target_value: return -1
    if target_value in options: return options.index(target_value)
    lower_target = str(target_value).lower().strip()
    for i, opt in enumerate(options):
        if str(opt).lower().strip() == lower_target:
            return i
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

# [NEW] Sanitize Step Data
def sanitize_step(step_data):
    keys_to_fix = {
        "next": "Next", "actionname": "ActionName", 
        "parameters": "Parameters", "default": "Default", 
        "choices": "Choices", "type": "Type", "end": "End",
        "resultpath": "ResultPath", "seconds": "Seconds"
    }
    existing_keys = list(step_data.keys())
    for k in existing_keys:
        k_lower = k.lower()
        if k_lower in keys_to_fix:
            target = keys_to_fix[k_lower]
            if k != target:
                val = step_data[k]
                if target not in step_data: step_data[target] = val
                del step_data[k]

# [CRITICAL] Sync Function
def try_sync_from_editor(new_content=None, force_ui_update=False):
    content = new_content if new_content is not None else st.session_state.get("editor_content", "")
    last_synced = st.session_state.get("last_synced_code", None)
    should_process = force_ui_update or (content != last_synced)
    
    if not should_process: return True, None

    if not content or not content.strip():
        if st.session_state.get("flow_json"):
            content = json.dumps(st.session_state["flow_json"], indent=2)
            st.session_state["editor_content"] = content
            st.session_state["last_synced_code"] = content
        else:
            return False, "Editor vazio."
    
    try:
        cleaned_content = clean_json_string(content)
        js = json.loads(cleaned_content)
        if "resources" in js:
            for v in js["resources"].values():
                if v.get("type") == "ZIS::Flow": 
                    js = v["properties"]["definition"]
                    break
        norm_js = normalize_zis_keys(clean_flow_logic(js))
        st.session_state["flow_json"] = norm_js
        st.session_state["last_synced_code"] = content
        st.session_state["ui_render_key"] += 1
        
        if force_ui_update:
            formatted_json = json.dumps(norm_js, indent=2)
            st.session_state["editor_content"] = formatted_json
            st.session_state["last_synced_code"] = formatted_json
            st.session_state["editor_key"] += 1
        return True, None
    except json.JSONDecodeError as e:
        return False, f"Erro JSON na linha {e.lineno}: {e.msg}"
    except Exception as e:
        return False, str(e)

# ==========================================
# 1. THEME & CONFIG
# ==========================================
st.set_page_config(page_title="ZIS Studio Beta", layout="wide", page_icon="⚡", initial_sidebar_state="expanded")

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
if "ui_render_key" not in st.session_state: st.session_state["ui_render_key"] = 0
if "editor_content" not in st.session_state:
    content = json.dumps(st.session_state["flow_json"], indent=2)
    st.session_state["editor_content"] = content
    st.session_state["last_synced_code"] = content

for key in ["zd_subdomain", "zd_email", "zd_token"]:
    if key not in st.session_state: st.session_state[key] = ""

from zis_engine import ZISFlowEngine

# ==========================================
# 3. HELPERS & STATIC SVG RENDERER
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

# [NEW] Static SVG Renderer with Post-Process Highlighting
# This is the ultimate fix for stability:
# 1. Generate Graphviz geometry WITHOUT knowing selected step (Input is identical = Layout is identical)
# 2. Inject CSS style block into SVG string to highlight specific ID (Output changes color only)
def render_flow_static_svg(flow_def, highlight_path=None, selected_step=None):
    if not HAS_GRAPHVIZ: 
        return st.warning("Graphviz not installed. Please add 'graphviz' to requirements.txt")

    try:
        # 1. Create Graph with FIXED Geometry Settings
        dot = graphviz.Digraph(format='svg')
        dot.attr(rankdir='TB', splines='polyline')
        dot.attr(nodesep='0.6', ranksep='0.7')
        
        # Standard Node Attributes
        dot.attr('node', shape='box', style='filled,rounded', 
                 fillcolor='#ECECFF', color='#939393', penwidth='2',
                 fontname='Arial', fontsize='12', margin='0.2')
        dot.attr('edge', color='#666666', penwidth='1.5', arrowsize='0.8')

        states = get_zis_key(flow_def, "States", {})
        start_step = get_zis_key(flow_def, "StartAt")

        # 2. Define Nodes (Strictly Sorted)
        # ID attribute is crucial for CSS targeting later
        # NOTE: We do NOT use 'selected_step' inside this loop to prevent layout changes
        dot.node("START", "Start", shape="circle", fillcolor="#4CAF50", color="#388E3C", width="0.8", fontcolor="white", id="node_START")
        dot.node("END", "End", shape="doublecircle", fillcolor="#333333", color="#000000", width="0.7", fontcolor="white", id="node_END")

        sorted_items = sorted(states.items())
        for k, v in sorted_items:
            sType = get_zis_key(v, "Type", "Unknown")
            label = f"{k}\n[{sType}]"
            
            # Generate Node with ID matching the Step Name
            # We enforce a sanitized ID to be safe for CSS selectors
            safe_id = re.sub(r'[^a-zA-Z0-9]', '_', k)
            dot.node(k, label, id=f"node_{safe_id}")

        # 3. Define Edges
        if start_step: dot.edge("START", start_step)

        for k, v in sorted_items:
            next_step = get_zis_key(v, "Next")
            if next_step: dot.edge(k, next_step)
            
            default_step = get_zis_key(v, "Default")
            if default_step: dot.edge(k, default_step, label="Default")
            
            choices = get_zis_key(v, "Choices", [])
            for c in choices:
                c_next = get_zis_key(c, "Next")
                if c_next: dot.edge(k, c_next, label="Match")
            
            # End Connection Logic
            sType = get_zis_key(v, "Type", "Unknown")
            is_explicit_end = get_zis_key(v, "End", False)
            is_terminal = sType in ["Succeed", "Fail"]
            
            if is_explicit_end or is_terminal:
                dot.edge(k, "END")

        # 4. Generate Raw SVG String
        svg_bytes = dot.pipe()
        svg_str = svg_bytes.decode('utf-8')
        
        # 5. CSS INJECTION FOR SELECTION
        # We inject a <style> block directly into the SVG to highlight the selected ID.
        # This changes colors WITHOUT recalculating layout.
        if selected_step:
            safe_sel_id = re.sub(r'[^a-zA-Z0-9]', '_', selected_step)
            # We target the polygon/path inside the group with the ID
            # Usually Graphviz wraps node content in a group <g id="node_XXX" ...>
            style_block = f"""
            <style>
                g[id="node_{safe_sel_id}"] path, 
                g[id="node_{safe_sel_id}"] polygon,
                g[id="node_{safe_sel_id}"] ellipse {{
                    fill: #FFF59D !important;
                    stroke: #FBC02D !important;
                    stroke-width: 4px !important;
                }}
            </style>
            """
            # Insert style right after <svg ...> tag
            # We regex search for the end of the svg opening tag
            match = re.search(r'<svg[^>]*>', svg_str)
            if match:
                insert_idx = match.end()
                svg_str = svg_str[:insert_idx] + style_block + svg_str[insert_idx:]

        # 6. Render as HTML (Native SVG)
        # Using a div with center alignment
        st.markdown(f"""
            <div style="width: 100%; overflow-x: auto; text-align: center; padding: 10px; border: 1px solid #ddd; border-radius: 10px; background-color: white;">
                {svg_str}
            </div>
            """, unsafe_allow_html=True)

    except Exception as e:
        st.error(f"Render Error: {e}")
        st.caption("Certifique-se de que 'graphviz' está instalado no requirements.txt")

# ==========================================
# 4. MAIN WORKSPACE
# ==========================================
st.title("ZIS Studio")
t_set, t_imp, t_code, t_vis, t_dep, t_deb = st.tabs(["⚙️ Settings", "📥 Import", "📝 Code Editor", "🎨 Visual Designer", "🚀 Deploy", "🐞 Debugger"])

with t_set:
    st.markdown("### 🔑 Zendesk Credentials")
    c1, c2 = st.columns([1, 1])
    with c1:
        with st.container(border=True):
            st.text_input("Subdomain", key="zd_subdomain")
            st.text_input("Email", key="zd_email")
            st.text_input("API Token", key="zd_token", type="password")
            if st.button("Test Connection"):
                ok, msg = test_connection()
                if ok: st.session_state["is_connected"] = True; st.toast(msg, icon="✅") 
                else: st.toast(msg, icon="❌")
    with c2:
        if st.session_state.get("is_connected"): st.success(f"✅ Connected to: **{st.session_state.zd_subdomain}**")

with t_imp:
    st.markdown("### 🔎 Find Existing Flows")
    if not st.session_state.get("is_connected"): st.warning("Configure Settings first.")
    else:
        if st.button("🚀 Start Deep Scan"):
            try:
                resp = requests.get(f"{get_base_url()}/integrations", auth=get_auth())
                if resp.status_code == 200:
                    ints = resp.json().get("integrations", [])
                    res = []
                    for i in ints:
                        nm = i["name"]
                        b_resp = requests.get(f"{get_base_url()}/{nm}/bundles", auth=get_auth())
                        if b_resp.status_code == 200:
                            for b in b_resp.json().get("bundles", []):
                                res.append({"int": nm, "bun": b["name"], "uuid": b.get("uuid", "")})
                    st.session_state["scan_results"] = res
                    if res: st.success(f"Found {len(res)} bundles.")
                    else: st.warning("No bundles found.")
            except Exception as e: st.error(str(e))

        if "scan_results" in st.session_state:
            res = st.session_state["scan_results"]
            sel = st.selectbox("Flows", range(len(res)), format_func=lambda i: f"{res[i]['int']} / {res[i]['bun']}")
            if st.button("Load Flow"):
                it = res[sel]
                url = f"{get_base_url()}/{it['int']}/bundles/{it['uuid'] or it['bun']}"
                r = requests.get(url, auth=get_auth())
                if r.status_code == 200:
                    for v in r.json().get("resources", {}).values():
                        if "Flow" in v.get("type", ""):
                            n_def = normalize_zis_keys(clean_flow_logic(v["properties"]["definition"]))
                            st.session_state["flow_json"] = n_def
                            formatted_js = json.dumps(n_def, indent=2)
                            st.session_state["editor_content"] = formatted_js
                            st.session_state["last_synced_code"] = formatted_js
                            st.session_state["editor_key"] += 1
                            st.session_state["ui_render_key"] += 1
                            st.toast("Loaded!", icon="🎉"); time.sleep(0.5); force_refresh(); break

with t_code:
    dk = f"code_editor_{st.session_state['editor_key']}"
    if HAS_EDITOR:
        custom_buttons = [{
            "name": "Save", 
            "feather": "Save",
            "primary": True,
            "hasText": True,
            "alwaysOn": True,
            "commands": ["submit"],
            "style": {"top": "0.46rem", "right": "0.4rem"}
        }]

        resp = code_editor(
            st.session_state.get("editor_content", ""), 
            lang="json", 
            height=600, 
            key=dk, 
            buttons=custom_buttons,
            options={"showLineNumbers": True, "wrap": True, "autoClosingBrackets": True}
        )
        
        if resp and resp.get("text") and resp.get("type") != "submit":
             st.session_state["editor_content"] = resp["text"]

        if resp and resp.get("type") == "submit":
            current_text = resp.get("text", "")
            st.session_state["editor_content"] = current_text
            ok, err = try_sync_from_editor(new_content=current_text, force_ui_update=False)
            if ok: st.toast("Salvo com Sucesso!", icon="✅")
            else: st.error(f"❌ Erro de Sintaxe: {err}")

with t_vis:
    ok, err = try_sync_from_editor(force_ui_update=False)
    ui_key = st.session_state["ui_render_key"]
    
    if not ok: st.error(f"⚠️ Invalid JSON: {err}")
    else:
        c1, c2 = st.columns([1, 2])
        curr = st.session_state["flow_json"]
        states = get_zis_key(curr, "States", {})
        keys = list(states.keys())
        with c1:
            st.subheader("Config")
            sel = st.selectbox("Step", ["(Select)"] + keys, key=f"step_selector_{ui_key}")
            
            with st.expander("➕ Add Step"):
                nn = st.text_input("Name"); nt = st.selectbox("Type", ["Action", "Choice", "Wait", "Pass", "Succeed", "Fail"])
                if st.button("Add"): 
                    st.session_state["flow_json"]["States"][nn] = {"Type": nt, "End": True} if nt == "Pass" else {"Type": nt}
                    formatted = json.dumps(st.session_state["flow_json"], indent=2)
                    st.session_state["editor_content"] = formatted
                    st.session_state["last_synced_code"] = formatted
                    st.session_state["ui_render_key"] += 1
                    force_refresh()
            
            st.divider()
            if sel != "(Select)" and sel in states:
                s_dat = states[sel]; sanitize_step(s_dat); s_typ = get_zis_key(s_dat, "Type")
                st.markdown(f"### {sel} `[{s_typ}]`")
                if s_typ not in ["Succeed", "Fail", "Choice"]:
                    is_end = st.checkbox("End Flow?", get_zis_key(s_dat, "End", False), key=f"end_{sel}_{ui_key}")
                    if is_end: s_dat["End"] = True; s_dat.pop("Next", None)
                    else:
                        s_dat.pop("End", None)
                        nxt_opts = [k for k in keys if k != sel]
                        curr_nxt = get_zis_key(s_dat, "Next", "")
                        idx = find_best_match_index(nxt_opts, curr_nxt)
                        final_idx = 0 if idx == -1 else idx
                        new_nxt = st.selectbox("Next", ["(Select)"] + nxt_opts, index=final_idx, key=f"nxt_{sel}_{ui_key}")
                        if new_nxt != "(Select)": s_dat["Next"] = new_nxt

                if s_typ == "Action":
                    s_dat["ActionName"] = st.text_input("Action", get_zis_key(s_dat, "ActionName", ""), key=f"act_{sel}_{ui_key}")
                    current_params = get_zis_key(s_dat, "Parameters", {})
                    param_str = json.dumps(current_params, indent=2)
                    new_param_str = st.text_area("Params", param_str, key=f"prm_{sel}_{ui_key}")
                    try:
                        s_dat["Parameters"] = json.loads(new_param_str)
                    except:
                        st.caption("❌ Invalid JSON in Params")
                    s_dat["ResultPath"] = st.text_input("ResultPath (e.g. $.myVar)", get_zis_key(s_dat, "ResultPath", ""), key=f"res_{sel}_{ui_key}")

                elif s_typ == "Choice":
                    s_dat["Default"] = st.selectbox("Default", [k for k in keys if k != sel], index=find_best_match_index([k for k in keys if k != sel], get_zis_key(s_dat, "Default")), key=f"def_{sel}_{ui_key}")
                    chs = get_zis_key(s_dat, "Choices", [])
                    if not isinstance(chs, list): chs = []
                    s_dat["Choices"] = chs
                    for i, ch in enumerate(chs):
                        with st.expander(f"Rule {i+1}"):
                            ch["Variable"] = st.text_input("Var", get_zis_key(ch, "Variable", ""), key=f"cv_{i}_{sel}_{ui_key}")
                            ops = ["StringEquals", "BooleanEquals", "NumericEquals", "NumericGreaterThan"]
                            curr_op = "StringEquals"; curr_val = ""
                            for op in ops:
                                if get_zis_key(ch, op) is not None: curr_op = op; curr_val = get_zis_key(ch, op); break
                            new_op = st.selectbox("Op", ops, index=ops.index(curr_op), key=f"cop_{i}_{sel}_{ui_key}")
                            new_val = st.text_input("Val", str(curr_val), key=f"cqv_{i}_{sel}_{ui_key}")
                            for op in ops: ch.pop(op, None); ch.pop(op.lower(), None)
                            real_val = new_val
                            if "Numeric" in new_op: 
                                try: real_val = float(new_val)
                                except: pass
                            ch[new_op] = real_val
                            ch["Next"] = st.selectbox("GoTo", [k for k in keys if k != sel], index=find_best_match_index([k for k in keys if k != sel], get_zis_key(ch, "Next")), key=f"cn_{i}_{sel}_{ui_key}")
                            if st.button("Del", key=f"cd_{i}_{sel}_{ui_key}"): chs.pop(i); force_refresh()
                    if st.button("Add Rule", key=f"ar_{sel}_{ui_key}"): chs.append({"Variable": "$.", "StringEquals": "", "Next": ""}); force_refresh()

                if st.button("Save Changes", type="primary", key=f"sv_{sel}_{ui_key}"):
                    new_code = json.dumps(st.session_state["flow_json"], indent=2)
                    st.session_state["editor_content"] = new_code
                    st.session_state["last_synced_code"] = new_code
                    st.session_state["editor_key"] += 1
                    st.success("Saved"); force_refresh()

        with c2:
            render_flow_static_svg(curr, selected_step=sel if sel != "(Select)" else None)

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
        render_flow_static_svg(st.session_state["flow_json"], current_path)