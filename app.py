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

# [HELPER] Normalize Logic
def normalize_zis_keys(obj):
    if isinstance(obj, dict):
        new_obj = {}
        # Keys for Flows
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
            "ispresent": "IsPresent", "isnull": "IsNull", "seconds": "Seconds",
            # New Keys for Actions/JobSpecs
            "url": "url", "method": "method", "headers": "headers", "requestbody": "requestBody",
            "event_source": "event_source", "event_type": "event_type", "target_flow": "target_flow"
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

def clean_resource_definition(res_data):
    if not isinstance(res_data, dict): return res_data
    clean = res_data.copy()
    # Remove meta properties that don't belong in the "definition" part
    forbidden_keys = ["zis_template_version", "resources", "name", "description", "type", "properties"]
    for key in forbidden_keys:
        if key in clean: del clean[key]
    return clean

# [NEW] Sanitize Step Data (Specific for Flows)
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

# [CRITICAL] Sync Function - UPDATED FOR MULTI-RESOURCE
def try_sync_from_editor(new_content=None, force_ui_update=False):
    content = new_content if new_content is not None else st.session_state.get("editor_content", "")
    last_synced = st.session_state.get("last_synced_code", None)
    should_process = force_ui_update or (content != last_synced)
    
    current_res_key = st.session_state.get("selected_resource_key")
    if not current_res_key: return True, None

    if not should_process: return True, None

    if not content or not content.strip():
        # Revert to current state if empty
        curr_res = st.session_state["bundle_resources"].get(current_res_key, {})
        def_content = curr_res.get("properties", {}).get("definition", {})
        content = json.dumps(def_content, indent=2)
        st.session_state["editor_content"] = content
        st.session_state["last_synced_code"] = content
        return False, "Editor vazio."
    
    try:
        cleaned_content = clean_json_string(content)
        js = json.loads(cleaned_content)
        
        # If user pasted a full resource object, extract just definition
        if "properties" in js and "definition" in js["properties"]:
            js = js["properties"]["definition"]
        elif "definition" in js:
            js = js["definition"]

        norm_js = normalize_zis_keys(clean_resource_definition(js))
        
        # Update Bundle State
        st.session_state["bundle_resources"][current_res_key]["properties"]["definition"] = norm_js
        
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
st.set_page_config(page_title="ZIS Studio Multi-Resource", layout="wide", page_icon="⚡")

st.markdown("""
<style>
    header {visibility: hidden;}
    .block-container { padding-top: 1rem; padding-bottom: 2rem; }
    /* Ensure sidebar is not forcefully hidden if we ever use it, but we are moving to main */
    [data-testid="stSidebar"] { display: none; } 
    [data-testid="collapsedControl"] { display: none; }
</style>
""", unsafe_allow_html=True)

# [STATE INITIALIZATION]
if "bundle_resources" not in st.session_state:
    # Default Template: 1 Flow, 1 Action, 1 Job Spec
    st.session_state["bundle_resources"] = {
        "my_flow": {
            "type": "ZIS::Flow",
            "properties": {
                "name": "my_flow",
                "definition": {"StartAt": "StartStep", "States": {"StartStep": {"Type": "Pass", "End": True}}}
            }
        },
        "my_action": {
            "type": "ZIS::Action::Http",
            "properties": {
                "name": "my_action",
                "definition": {
                    "url": "https://httpbin.org/post",
                    "method": "POST",
                    "headers": [{"key": "Content-Type", "value": "application/json"}],
                    "requestBody": {"info": "Hello from ZIS"}
                }
            }
        },
        "my_job_spec": {
            "type": "ZIS::JobSpec",
            "properties": {
                "name": "my_job_spec",
                "definition": {
                    "event_source": "support",
                    "event_type": "ticket.created",
                    "target_flow": "zis:integration:default:my_flow"
                }
            }
        }
    }

if "selected_resource_key" not in st.session_state: 
    # Auto select first available if any
    if st.session_state["bundle_resources"]:
        st.session_state["selected_resource_key"] = list(st.session_state["bundle_resources"].keys())[0]
    else:
        st.session_state["selected_resource_key"] = ""

if "editor_key" not in st.session_state: st.session_state["editor_key"] = 0 
if "ui_render_key" not in st.session_state: st.session_state["ui_render_key"] = 0

# Initial Editor Content Load
if st.session_state["selected_resource_key"] and "editor_content" not in st.session_state:
    cur_key = st.session_state["selected_resource_key"]
    cur_def = st.session_state["bundle_resources"][cur_key]["properties"]["definition"]
    content = json.dumps(cur_def, indent=2)
    st.session_state["editor_content"] = content
    st.session_state["last_synced_code"] = content

# Cache for SVG
if "cached_svg" not in st.session_state: st.session_state["cached_svg"] = None
if "cached_svg_version" not in st.session_state: st.session_state["cached_svg_version"] = -1

for key in ["zd_subdomain", "zd_email", "zd_token"]:
    if key not in st.session_state: st.session_state[key] = ""

from zis_engine import ZISFlowEngine, ZISActionTester

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
    est_height = 200 + (len(get_zis_key(flow_def, "States", {})) * 120)
    components.html(full_html, height=est_height, scrolling=True)


# ==========================================
# 4. REUSABLE RESOURCE MANAGER COMPONENT
# ==========================================
def render_resource_manager(location_key):
    """
    Renders the Resource Manager UI. 
    'location_key' ensures unique widget IDs if this function is called in multiple tabs.
    """
    with st.container(border=True):
        st.markdown(f"**🗂️ Gerenciador de Recursos**")
        
        res_map = st.session_state["bundle_resources"]
        res_keys = list(res_map.keys())
        
        col_sel, col_type, col_act = st.columns([2, 1, 1])
        
        with col_sel:
            if not res_keys:
                 st.warning("No resources. Create one below.")
                 selected_key = None
            else:
                # Sync logic: Ensure the selectbox reflects the global session state
                curr_val = st.session_state.get("selected_resource_key")
                curr_idx = res_keys.index(curr_val) if curr_val in res_keys else 0
                
                selected_key = st.selectbox(
                    "Selecione o Arquivo", 
                    res_keys, 
                    index=curr_idx, 
                    key=f"res_sel_{location_key}"
                )

        if selected_key:
            # Sync Global State if Widget Changed
            if selected_key != st.session_state.get("selected_resource_key"):
                st.session_state["selected_resource_key"] = selected_key
                
                # Update Content for Editor
                new_def = res_map[selected_key]["properties"]["definition"]
                formatted_json = json.dumps(new_def, indent=2)
                st.session_state["editor_content"] = formatted_json
                st.session_state["last_synced_code"] = formatted_json
                st.session_state["editor_key"] += 1
                st.session_state["ui_render_key"] += 1
                st.session_state["cached_svg"] = None
                force_refresh()

            current_res = res_map[selected_key]
            current_type = current_res.get("type", "Unknown")
            
            with col_type:
                st.info(f"Type:\n**{current_type}**")
            
            with col_act:
                if len(res_keys) > 1:
                    if st.button("🗑️ Deletar", type="secondary", key=f"del_{location_key}"):
                        del st.session_state["bundle_resources"][selected_key]
                        st.session_state["selected_resource_key"] = list(st.session_state["bundle_resources"].keys())[0]
                        force_refresh()
                else:
                    st.caption("Cannot delete last item")

        # Create New Resource Expander
        with st.expander("➕ Adicionar Novo Recurso"):
            c_new_1, c_new_2, c_new_3 = st.columns([2, 2, 1])
            with c_new_1:
                new_res_name = st.text_input("Nome", key=f"nrn_{location_key}")
            with c_new_2:
                new_res_type = st.selectbox("Tipo", ["ZIS::Flow", "ZIS::Action::Http", "ZIS::JobSpec"], key=f"nrt_{location_key}")
            with c_new_3:
                st.write("") 
                st.write("") 
                if st.button("Criar", key=f"btn_create_{location_key}"):
                    safe_name = new_res_name.lower().strip().replace(" ", "_")
                    if safe_name and safe_name not in res_map:
                        def_def = {}
                        if new_res_type == "ZIS::Flow":
                            def_def = {"StartAt": "StartStep", "States": {"StartStep": {"Type": "Pass", "End": True}}}
                        elif new_res_type == "ZIS::Action::Http":
                            def_def = {"url": "https://", "method": "GET"}
                        elif new_res_type == "ZIS::JobSpec":
                            def_def = {"event_source": "zendesk", "event_type": "ticket.saved", "target_flow": ""}
                        
                        st.session_state["bundle_resources"][safe_name] = {
                            "type": new_res_type,
                            "properties": {"name": safe_name, "definition": def_def}
                        }
                        st.session_state["selected_resource_key"] = safe_name 
                        st.success(f"Criado: {safe_name}")
                        time.sleep(0.5)
                        force_refresh()
                    else:
                        st.error("Nome inválido ou duplicado")

# ==========================================
# 5. MAIN PAGE
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
    st.markdown("### 🔎 Import Bundle")
    if not st.session_state.get("is_connected"): st.warning("Configure Settings first.")
    else:
        st.info("This will overwrite your current workspace with the imported bundle.")
        if st.button("🚀 Start Deep Scan"):
            try:
                with st.status("🔍 Scanning Zendesk Integrations...", expanded=True) as status:
                    status.write("Fetching Integrations list...")
                    resp = requests.get(f"{get_base_url()}/integrations", auth=get_auth())
                    
                    if resp.status_code == 200:
                        ints = resp.json().get("integrations", [])
                        total_ints = len(ints)
                        status.write(f"Found {total_ints} integrations. Scanning bundles...")
                        progress_bar = status.progress(0)
                        
                        res = []
                        for idx, i in enumerate(ints):
                            nm = i["name"]
                            progress = (idx + 1) / total_ints
                            progress_bar.progress(progress)
                            try:
                                b_resp = requests.get(f"{get_base_url()}/{nm}/bundles", auth=get_auth())
                                if b_resp.status_code == 200:
                                    bundles = b_resp.json().get("bundles", [])
                                    for b in bundles:
                                        res.append({"int": nm, "bun": b["name"], "uuid": b.get("uuid", "")})
                            except: pass
                        st.session_state["scan_results"] = res
                        status.update(label=f"Found {len(res)} bundles.", state="complete", expanded=False)
                    else:
                        st.error(f"API Error: {resp.status_code}")
            except Exception as e: st.error(str(e))

        if "scan_results" in st.session_state:
            res = st.session_state["scan_results"]
            sel = st.selectbox("Bundles", range(len(res)), format_func=lambda i: f"{res[i]['int']} / {res[i]['bun']}")
            if st.button("Load Bundle"):
                it = res[sel]
                url = f"{get_base_url()}/{it['int']}/bundles/{it['uuid'] or it['bun']}"
                r = requests.get(url, auth=get_auth())
                if r.status_code == 200:
                    # [NEW IMPORT LOGIC]
                    imported_resources = r.json().get("resources", {})
                    new_bundle_map = {}
                    
                    for res_key, res_data in imported_resources.items():
                        r_type = res_data.get("type")
                        r_props = res_data.get("properties", {})
                        r_def = r_props.get("definition", {})
                        
                        # Clean definition
                        clean_def = normalize_zis_keys(clean_resource_definition(r_def))
                        r_props["definition"] = clean_def
                        res_data["properties"] = r_props
                        
                        new_bundle_map[res_key] = res_data
                    
                    if new_bundle_map:
                        st.session_state["bundle_resources"] = new_bundle_map
                        # Select first flow or first item
                        first_key = list(new_bundle_map.keys())[0]
                        for k, v in new_bundle_map.items():
                            if v.get("type") == "ZIS::Flow":
                                first_key = k; break
                        
                        st.session_state["selected_resource_key"] = first_key
                        
                        # Trigger Editor Refresh
                        formatted_js = json.dumps(new_bundle_map[first_key]["properties"]["definition"], indent=2)
                        st.session_state["editor_content"] = formatted_js
                        st.session_state["last_synced_code"] = formatted_js
                        st.session_state["editor_key"] += 1
                        st.session_state["ui_render_key"] += 1
                        st.session_state["cached_svg"] = None
                        
                        st.toast("Bundle Loaded!", icon="🎉"); time.sleep(0.5); force_refresh()
                    else:
                        st.warning("Bundle is empty.")

with t_code:
    # RENDER CONTEXTUAL MENU
    render_resource_manager("code_tab")
    st.divider()

    dk = f"code_editor_{st.session_state['editor_key']}"
    if HAS_EDITOR:
        custom_buttons = [{"name": "Save", "feather": "Save", "primary": True, "hasText": True, "alwaysOn": True, "commands": ["submit"], "style": {"top": "0.46rem", "right": "0.4rem"}}]

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
    # RENDER CONTEXTUAL MENU
    render_resource_manager("vis_tab")
    st.divider()

    ok, err = try_sync_from_editor(force_ui_update=False)
    
    current_res_obj = st.session_state["bundle_resources"][st.session_state["selected_resource_key"]]
    current_type = current_res_obj.get("type")
    current_def = current_res_obj["properties"]["definition"]
    ui_key = st.session_state["ui_render_key"]

    if not ok: st.error(f"⚠️ Invalid JSON: {err}")
    elif current_type == "ZIS::Flow":
        # ==========================================
        # EXISTING FLOW DESIGNER LOGIC
        # ==========================================
        c1, c2 = st.columns([1, 2])
        states = get_zis_key(current_def, "States", {})
        keys = list(states.keys())
        with c1:
            st.subheader("Flow Steps")
            sel = st.selectbox("Step", ["(Select)"] + keys, key=f"step_selector_{ui_key}")
            
            with st.expander("➕ Add Step"):
                nn = st.text_input("Name"); nt = st.selectbox("Type", ["Action", "Choice", "Wait", "Pass", "Succeed", "Fail"])
                if st.button("Add"): 
                    states[nn] = {"Type": nt, "End": True} if nt == "Pass" else {"Type": nt}
                    current_def["States"] = states # Ensure update
                    formatted = json.dumps(current_def, indent=2)
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
                    # Choice logic (same as before)
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
                            
                            idx_rule_next = find_best_match_index([k for k in keys if k != sel], get_zis_key(ch, "Next"))
                            final_idx_rule = idx_rule_next if idx_rule_next != -1 else 0
                            
                            ch["Next"] = st.selectbox("GoTo", [k for k in keys if k != sel], index=final_idx_rule, key=f"cn_{i}_{sel}_{ui_key}")
                            if st.button("Del", key=f"cd_{i}_{sel}_{ui_key}"): chs.pop(i); force_refresh()
                    if st.button("Add Rule", key=f"ar_{sel}_{ui_key}"): chs.append({"Variable": "$.", "StringEquals": "", "Next": ""}); force_refresh()

                if st.button("Save Changes", type="primary", key=f"sv_{sel}_{ui_key}"):
                    new_code = json.dumps(current_def, indent=2)
                    st.session_state["editor_content"] = new_code
                    st.session_state["last_synced_code"] = new_code
                    st.session_state["editor_key"] += 1
                    st.success("Saved"); force_refresh()

        with c2:
            render_flow_static_svg(current_def, selected_step=sel if sel != "(Select)" else None)
    
    elif current_type == "ZIS::Action::Http":
        st.info("🎨 Action Designer")
        c1, c2 = st.columns(2)
        with c1:
            current_def["method"] = st.selectbox("Method", ["GET", "POST", "PUT", "DELETE", "PATCH"], index=["GET", "POST", "PUT", "DELETE", "PATCH"].index(current_def.get("method", "GET")), key=f"mth_{ui_key}")
            current_def["url"] = st.text_input("URL", value=current_def.get("url", ""), key=f"url_{ui_key}")
        
        st.subheader("Headers")
        hdrs = current_def.get("headers", [])
        if not isinstance(hdrs, list): hdrs = [] 
        for i, h in enumerate(hdrs):
            hc1, hc2 = st.columns(2)
            h["key"] = hc1.text_input(f"Key #{i}", h.get("key", ""), key=f"hk_{i}_{ui_key}")
            h["value"] = hc2.text_input(f"Value #{i}", h.get("value", ""), key=f"hv_{i}_{ui_key}")
        if st.button("Add Header"):
            hdrs.append({"key": "", "value": ""})
            current_def["headers"] = hdrs; force_refresh()

        if st.button("Save Action", type="primary"):
            new_code = json.dumps(current_def, indent=2)
            st.session_state["editor_content"] = new_code
            st.session_state["last_synced_code"] = new_code
            st.success("Saved Action")

    elif current_type == "ZIS::JobSpec":
        st.info("🎨 Job Spec Configuration")
        current_def["event_source"] = st.text_input("Event Source", current_def.get("event_source", "zendesk"), key=f"es_{ui_key}")
        current_def["event_type"] = st.text_input("Event Type", current_def.get("event_type", "ticket.saved"), key=f"et_{ui_key}")
        current_def["target_flow"] = st.text_input("Target Flow Name (zis:integration:default:flow_name)", current_def.get("target_flow", ""), key=f"tf_{ui_key}")
        
        if st.button("Save Job Spec", type="primary"):
            new_code = json.dumps(current_def, indent=2)
            st.session_state["editor_content"] = new_code
            st.session_state["last_synced_code"] = new_code
            st.success("Saved Job Spec")
    else:
        st.warning(f"Visual Designer not available for {current_type}")


with t_dep:
    if not st.session_state.get("is_connected"): st.warning("Connect in Settings first.")
    else:
        st.markdown("### 🚀 Deploy Bundle")
        sub = st.session_state.get("zd_subdomain", "sub")
        default_int = f"zis_playground_{sub.lower().strip()}"
        with st.container(border=True):
            raw_int_name = st.text_input("Target Integration Name", value=default_int)
            target_int = raw_int_name.lower().strip().replace(" ", "_")
            bun_name = st.text_input("Bundle Name", value=st.session_state.get("current_bundle_name", "my_bundle"))
            
            if st.button("Deploy Bundle", type="primary"):
                with st.status("Deploying...") as status:
                    try:
                        status.write("Creating integration...")
                        requests.post(f"{get_base_url()}/integrations", auth=get_auth(), json={"name": target_int, "display_name": target_int}, headers={"Content-Type": "application/json"})
                        
                        safe_bun = bun_name.lower().strip().replace("-", "_").replace(" ", "")
                        
                        # [BUNDLE ASSEMBLY]
                        resources_payload = {}
                        res_map = st.session_state["bundle_resources"]
                        
                        for r_key, r_val in res_map.items():
                            r_copy = copy.deepcopy(r_val)
                            def_clean = clean_resource_definition(r_copy["properties"]["definition"])
                            r_copy["properties"]["definition"] = def_clean
                            resources_payload[r_key] = r_copy

                        payload = {
                            "zis_template_version": "2019-10-14", 
                            "name": safe_bun, 
                            "resources": resources_payload
                        }
                        
                        status.write(f"Uploading {len(resources_payload)} resources...")
                        r = requests.post(f"{get_base_url()}/{target_int}/bundles", auth=get_auth(), json=payload, headers={"Content-Type": "application/json"})
                        
                        if r.status_code in [200, 201]:
                            st.balloons(); status.update(label="Deployed!", state="complete"); st.success(f"Deployed {safe_bun} to {target_int}")
                            st.json(payload)
                        else:
                            status.update(label="Failed", state="error"); st.error(r.text)
                    except Exception as e: st.error(str(e))

with t_deb:
    # RENDER CONTEXTUAL MENU
    render_resource_manager("deb_tab")
    st.divider()

    current_res_obj = st.session_state["bundle_resources"][st.session_state["selected_resource_key"]]
    current_type = current_res_obj.get("type")
    current_def = current_res_obj["properties"]["definition"]

    if current_type == "ZIS::Flow":
        col_input, col_graph = st.columns([1, 1])
        with col_input:
            st.markdown("### Flow Simulation")
            inp = st.text_area("JSON Input", '{"ticket": {"id": 123}}', height=200, key="debug_input")
            if st.button("▶️ Run Simulation", type="primary"):
                eng = ZISFlowEngine(normalize_zis_keys(current_def), json.loads(inp), {}, {})
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
            render_flow_static_svg(current_def, current_path)
            
    elif current_type == "ZIS::Action::Http":
        st.markdown("### ⚡ Action Tester")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Action Definition**")
            st.json(current_def)
        with c2:
            st.markdown("**Test Parameters**")
            test_params = st.text_area("Parameters (JSON)", '{"id": 123}', height=150)
            
            if st.button("▶️ Test Action", type="primary"):
                try:
                    p_json = json.loads(test_params)
                    with st.spinner("Executing..."):
                        res = ZISActionTester.execute(current_def, p_json)
                    st.subheader("Response")
                    st.json(res)
                except json.JSONDecodeError:
                    st.error("Invalid JSON parameters")
                except Exception as e:
                    st.error(str(e))
    else:
        st.info("Debugger not available for Job Specs (Trigger logic only).")