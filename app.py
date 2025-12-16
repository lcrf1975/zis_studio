import streamlit as st
import json
import requests
import time
import re
import base64
import copy
import streamlit.components.v1 as components
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

# Cache for SVG
if "cached_svg" not in st.session_state: st.session_state["cached_svg"] = None
if "cached_svg_version" not in st.session_state: st.session_state["cached_svg_version"] = -1

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

# [NEW] CACHED SVG RENDERER - NATURAL SIZE
def render_flow_static_svg(flow_def, highlight_path=None, selected_step=None):
    if not HAS_GRAPHVIZ: 
        return st.warning("Graphviz not installed. Please add 'graphviz' to requirements.txt")

    current_ui_version = st.session_state.get("ui_render_key", 0)
    
    # 1. GENERATE BASE GRAPH (Only if flow changed)
    if st.session_state["cached_svg"] is None or st.session_state["cached_svg_version"] != current_ui_version:
        try:
            dot = graphviz.Digraph(format='svg')
            # Settings for better spacing
            dot.attr(rankdir='TB', splines='polyline', compound='true')
            dot.attr(nodesep='0.6', ranksep='0.8') 
            
            # Use strict attributes for all nodes
            dot.attr('node', shape='box', style='filled,rounded', 
                     fillcolor='#ECECFF', color='#939393', penwidth='2',
                     fontname='Arial', fontsize='12', margin='0.2')
            dot.attr('edge', color='#666666', penwidth='1.5', arrowsize='0.7')

            states = get_zis_key(flow_def, "States", {})
            start_step = get_zis_key(flow_def, "StartAt")

            # Nodes
            dot.node("START", "Start", shape="circle", fillcolor="#4CAF50", color="#388E3C", width="0.6", fontcolor="white", id="node_START", fontsize='10')
            dot.node("END", "End", shape="doublecircle", fillcolor="#333333", color="#000000", width="0.5", fontcolor="white", id="node_END", fontsize='10')

            # Sort items specifically for graph generation consistency
            sorted_items = sorted(states.items())
            
            for k, v in sorted_items:
                sType = get_zis_key(v, "Type", "Unknown")
                display_k = k if len(k) < 25 else k[:23] + ".."
                label = f"{display_k}\n[{sType}]"
                # Use a strictly alphanumeric ID for CSS targeting
                safe_id = re.sub(r'[^a-zA-Z0-9]', '_', k)
                dot.node(k, label, id=f"node_{safe_id}")

            # Edges
            if start_step: dot.edge("START", start_step)

            for k, v in sorted_items:
                next_step = get_zis_key(v, "Next")
                if next_step: dot.edge(k, next_step)
                default_step = get_zis_key(v, "Default")
                if default_step: dot.edge(k, default_step, label="Default", fontsize='10', fontcolor='#666')
                choices = get_zis_key(v, "Choices", [])
                for c in choices:
                    c_next = get_zis_key(c, "Next")
                    if c_next: dot.edge(k, c_next, label="Match", fontsize='10', fontcolor='#666')
                
                sType = get_zis_key(v, "Type", "Unknown")
                is_explicit_end = get_zis_key(v, "End", False)
                is_terminal = sType in ["Succeed", "Fail"]
                if is_explicit_end or is_terminal:
                    dot.edge(k, "END")

            # Get Raw SVG
            svg_bytes = dot.pipe()
            svg_str = svg_bytes.decode('utf-8')
            
            # [FIX] RESPONSIVENESS:
            # We clean XML headers but we DO NOT remove width/height attributes.
            # Graphviz calculates the perfect size for readability.
            # We let CSS scale it DOWN if needed (max-width), but not stretch it up.
            svg_str = re.sub(r'<\?xml.*?>', '', svg_str)
            svg_str = re.sub(r'<!DOCTYPE.*?>', '', svg_str)
            
            st.session_state["cached_svg"] = svg_str
            st.session_state["cached_svg_version"] = current_ui_version
            
        except Exception as e:
            st.error(f"Render Error: {e}")
            return

    # 2. RETRIEVE CACHED SVG
    final_svg = st.session_state["cached_svg"]
    
    # 3. GENERATE CSS FOR HIGHLIGHTS
    css_rules = []
    if selected_step:
        safe_sel_id = re.sub(r'[^a-zA-Z0-9]', '_', selected_step)
        css_rules.append(f"""
            #node_{safe_sel_id} polygon, #node_{safe_sel_id} path, #node_{safe_sel_id} ellipse {{
                fill: #FFF59D !important;
                stroke: #FBC02D !important;
                stroke-width: 3px !important;
            }}
        """)
        
    if highlight_path:
        for step in highlight_path:
            if step == selected_step: continue
            safe_id = re.sub(r'[^a-zA-Z0-9]', '_', step)
            css_rules.append(f"""
                #node_{safe_id} polygon, #node_{safe_id} path, #node_{safe_id} ellipse {{
                    fill: #C8E6C9 !important;
                    stroke: #4CAF50 !important;
                }}
            """)

    # 4. RENDER IN RESPONSIVE CONTAINER
    # max-width: 100% ensures it shrinks on small screens but doesn't blow up on large ones.
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <style>
        body {{ margin: 0; padding: 0; background: transparent; display: flex; justify-content: center; }}
        .svg-wrapper {{
            width: auto;
            max-width: 100%;
            padding: 10px;
            box-sizing: border-box;
        }}
        svg {{
            max-width: 100%; /* Shrink if too wide */
            height: auto;    /* Maintain aspect ratio */
            display: block;  /* Remove inline gaps */
        }}
        { "".join(css_rules) }
    </style>
    </head>
    <body>
        <div class="svg-wrapper">
            {final_svg}
        </div>
    </body>
    </html>
    """
    
    # Estimate height generously so Streamlit allocates space. 
    est_height = 200 + (len(get_zis_key(flow_def, "States", {})) * 120)
    components.html(full_html, height=est_height, scrolling=True)

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
                # [FIX] Enhanced Progress Bar Logic
                # Use st.status for better UX during long operations
                with st.status("🔍 Scanning Zendesk Integrations...", expanded=True) as status:
                    
                    status.write("Fetching Integrations list...")
                    resp = requests.get(f"{get_base_url()}/integrations", auth=get_auth())
                    
                    if resp.status_code == 200:
                        ints = resp.json().get("integrations", [])
                        total_ints = len(ints)
                        status.write(f"Found {total_ints} integrations. Scanning bundles...")
                        
                        # Create progress bar inside the status container
                        progress_bar = status.progress(0)
                        
                        res = []
                        for idx, i in enumerate(ints):
                            nm = i["name"]
                            # Update progress
                            progress = (idx + 1) / total_ints
                            progress_bar.progress(progress)
                            
                            try:
                                b_resp = requests.get(f"{get_base_url()}/{nm}/bundles", auth=get_auth())
                                if b_resp.status_code == 200:
                                    bundles = b_resp.json().get("bundles", [])
                                    for b in bundles:
                                        res.append({"int": nm, "bun": b["name"], "uuid": b.get("uuid", "")})
                            except:
                                pass # Skip faulty integrations silently to keep scanning
                        
                        st.session_state["scan_results"] = res
                        
                        if res: 
                            status.update(label=f"✅ Scan Complete! Found {len(res)} bundles.", state="complete", expanded=False)
                            st.success(f"Found {len(res)} bundles.")
                        else: 
                            status.update(label="⚠️ Scan Complete. No bundles found.", state="complete", expanded=False)
                            st.warning("No bundles found.")
                    else:
                        status.update(label="❌ API Error", state="error")
                        st.error(f"API Error: {resp.status_code}")
                        
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
                        
                        # [FIX] Offset +1 because we prepend "(Select)" to the list
                        # If idx is -1 (not found), we use 0 to select "(Select)"
                        final_idx = (idx + 1) if idx != -1 else 0
                        
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
                    # [FIX] Safe index finding for Default choice
                    idx_def = find_best_match_index([k for k in keys if k != sel], get_zis_key(s_dat, "Default"))
                    final_idx_def = idx_def if idx_def != -1 else 0
                    
                    s_dat["Default"] = st.selectbox("Default", [k for k in keys if k != sel], index=final_idx_def, key=f"def_{sel}_{ui_key}")
                    
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
                            
                            # [FIX] Safe index finding for Rules Next
                            idx_rule_next = find_best_match_index([k for k in keys if k != sel], get_zis_key(ch, "Next"))
                            final_idx_rule = idx_rule_next if idx_rule_next != -1 else 0
                            
                            ch["Next"] = st.selectbox("GoTo", [k for k in keys if k != sel], index=final_idx_rule, key=f"cn_{i}_{sel}_{ui_key}")
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
                        
                        # [FIXED LOGIC START] ========================
                        # Auto-fix Action Names to meet ZIS requirements AND generate missing resources
                        status.write("Validating Action Names & Generating Placeholders...")
                        final_def = copy.deepcopy(norm_def)
                        states_to_fix = final_def.get("States", {})
                        
                        generated_actions = {} # Store auto-generated resource definitions
                        
                        for s_name, s_body in states_to_fix.items():
                            # Fix 3: Sanitize ResultPath
                            if "ResultPath" in s_body:
                                rp = s_body["ResultPath"]
                                if not rp or rp.strip() == "" or rp.strip() == "$.":
                                    del s_body["ResultPath"]

                            if s_body.get("Type") == "Action":
                                a_name = s_body.get("ActionName", "")
                                
                                # Fix 1: ZIS Common Transform -> Jq
                                if a_name == "ZIS::Common::Transform":
                                    s_body["ActionName"] = "zis:common:transform:Jq"
                                    
                                    # Fix 1b: Convert data object to string if needed
                                    params = s_body.get("Parameters", {})
                                    if "data" in params and isinstance(params["data"], (dict, list)):
                                        params["data"] = json.dumps(params["data"])

                                # Fix 2: Custom Actions
                                elif a_name and not a_name.startswith("zis:"):
                                    simple_name = a_name
                                    new_full_name = f"zis:{target_int}:action:{simple_name}"
                                    s_body["ActionName"] = new_full_name
                                    
                                    # [NEW] Generate Placeholder Resource if it doesn't exist
                                    # We use the 'simple_name' as the resource key in the bundle
                                    if simple_name not in generated_actions:
                                        generated_actions[simple_name] = {
                                            "type": "ZIS::Action::Http",
                                            "properties": {
                                                "name": simple_name,
                                                "definition": {
                                                    "method": "POST",
                                                    "url": f"https://example.com/placeholder/{simple_name}",
                                                    # FIX: Headers must be an array of objects
                                                    "headers": [
                                                        {"key": "Content-Type", "value": "application/json"}
                                                    ],
                                                    # FIX: use requestBody instead of body
                                                    "requestBody": {
                                                        "info": f"Auto-generated placeholder for {simple_name}."
                                                    }
                                                }
                                            }
                                        }

                        # Prepare Bundle Payload
                        resources_payload = {
                            res_name: {
                                "type": "ZIS::Flow",
                                "properties": {"name": res_name, "definition": final_def}
                            }
                        }
                        
                        # Inject generated actions into resources
                        if generated_actions:
                            status.write(f"⚠️ Auto-generated {len(generated_actions)} placeholder actions.")
                            resources_payload.update(generated_actions)

                        payload = {
                            "zis_template_version": "2019-10-14", 
                            "name": safe_bun, 
                            "resources": resources_payload
                        }
                        # [FIXED LOGIC END] ==========================

                        r = requests.post(f"{get_base_url()}/{target_int}/bundles", auth=get_auth(), json=payload, headers={"Content-Type": "application/json"})
                        if r.status_code in [200, 201]:
                            st.balloons(); status.update(label="Deployed!", state="complete"); st.success(f"Deployed {safe_bun} to {target_int}")
                            
                            # [MODIFIED] Store results for confirmation instead of applying directly
                            st.session_state["pending_deployment_fix"] = final_def
                            st.session_state["pending_generated_actions"] = generated_actions
                            
                        else:
                            status.update(label="Failed", state="error"); st.error(r.text)
                    except Exception as e: st.error(str(e))

            # [NEW] Confirmation Block (Outside Deploy Button Scope)
            if "pending_deployment_fix" in st.session_state:
                # Use a placeholder to prevent visual glitches/duplication on refresh
                confirm_container = st.empty()
                
                with confirm_container.container():
                    st.divider()
                    st.info("The ZIS Studio found and fixed your code to enable the deployment. Would you like to apply these fixes to your code in the Code Editor?")
                    
                    c_yes, c_no = st.columns([1, 4])
                    with c_yes:
                        if st.button("✅ Yes, Apply Fixes"):
                            final_def = st.session_state["pending_deployment_fix"]
                            
                            # 1. Update Core State (Source of Truth)
                            st.session_state["flow_json"] = final_def
                            
                            # 2. Update Editor State
                            new_editor_code = json.dumps(final_def, indent=2)
                            st.session_state["editor_content"] = new_editor_code
                            st.session_state["last_synced_code"] = new_editor_code
                            st.session_state["editor_key"] += 1
                            
                            # 3. Update Visuals & Debugger
                            st.session_state["ui_render_key"] += 1
                            st.session_state["cached_svg"] = None
                            if "debug_res" in st.session_state: 
                                del st.session_state["debug_res"]
                            
                            # 4. Cleanup
                            del st.session_state["pending_deployment_fix"]
                            if "pending_generated_actions" in st.session_state: 
                                del st.session_state["pending_generated_actions"]
                            
                            st.toast("Code, Visuals & Debugger updated!", icon="🎉")
                            
                            # Clear UI immediately before rerun to avoid duplication glitch
                            confirm_container.empty()
                            
                            time.sleep(1)
                            force_refresh()
                    
                    with c_no:
                        if st.button("❌ No"):
                            del st.session_state["pending_deployment_fix"]
                            if "pending_generated_actions" in st.session_state: del st.session_state["pending_generated_actions"]
                            
                            # Clear UI immediately
                            confirm_container.empty()
                            
                            force_refresh()

                    # Warning about Generated Actions
                    gen_acts = st.session_state.get("pending_generated_actions", {})
                    if gen_acts:
                        st.warning(f"Note: {len(gen_acts)} actions were created as placeholders (pointing to example.com). You must update them in the Zendesk Registry for them to work.")

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