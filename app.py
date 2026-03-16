from zis_engine import ZISFlowEngine
import streamlit as st
import json
import requests
import time
import re
import copy
import hashlib
import streamlit.components.v1 as components
from requests.auth import HTTPBasicAuth

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
    st.rerun()


# [HELPER] Robust JSON Cleaner


def clean_json_string(json_str):
    if not isinstance(json_str, str):
        return ""
    json_str = json_str.strip()
    json_str = re.sub(r"^```[a-zA-Z]*\s*", "", json_str)
    json_str = re.sub(r"\s*```$", "", json_str)
    json_str = json_str.replace("\u00a0", " ")

    pattern = r'("[^"\\]*(?:\\.[^"\\]*)*")|(/\*[\s\S]*?\*/)|(//.*)'

    def replace(match):
        if match.group(1):
            return match.group(1)
        return ""

    try:
        return re.sub(pattern, replace, json_str)
    except Exception:
        return json_str


# [HELPER] Robust Key Reader


def get_zis_key(data, key, default=None):
    if not isinstance(data, dict):
        return default
    if key in data:
        return data[key]
    lower_key = key.lower()
    for k, v in data.items():
        if k.lower() == lower_key:
            return v
    return default


# [HELPER] Smart Index Finder


def find_best_match_index(options, target_value):
    if not target_value:
        return -1
    if target_value in options:
        return options.index(target_value)
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
            "startat": "StartAt",
            "states": "States",
            "type": "Type",
            "next": "Next",
            "default": "Default",
            "choices": "Choices",
            "parameters": "Parameters",
            "actionname": "ActionName",
            "end": "End",
            "comment": "Comment",
            "definition": "Definition",
            "inputpath": "InputPath",
            "outputpath": "OutputPath",
            "resultpath": "ResultPath",
            "result": "Result",
            "itemspath": "ItemsPath",
            "cause": "Cause",
            "error": "Error",
            "catch": "Catch",
            "retry": "Retry",
            "errorequals": "ErrorEquals",
            "variable": "Variable",
            # Operators
            "stringequals": "StringEquals",
            "stringmatches": "StringMatches",
            "stringlessthan": "StringLessThan",
            "stringlessthanequals": "StringLessThanEquals",
            "stringgreaterthan": "StringGreaterThan",
            "stringgreaterthanequals": "StringGreaterThanEquals",
            "booleanequals": "BooleanEquals",
            "numericequals": "NumericEquals",
            "numericgreaterthan": "NumericGreaterThan",
            "numericgreaterthanequals": "NumericGreaterThanEquals",
            "numericlessthan": "NumericLessThan",
            "numericlessthanequals": "NumericLessThanEquals",
            "timestampequals": "TimestampEquals",
            "timestamptlessthan": "TimestampLessThan",
            "timestamptlessthanequals": "TimestampLessThanEquals",
            "timestamptgreaterthan": "TimestampGreaterThan",
            "timestamptgreaterthanequals": "TimestampGreaterThanEquals",
            "ispresent": "IsPresent",
            "isnull": "IsNull",
            "seconds": "Seconds",
            # New Keys for Actions/JobSpecs
            "url": "url",
            "method": "method",
            "headers": "headers",
            "requestbody": "requestBody",
            "event_source": "event_source",
            "event_type": "event_type",
            "target_flow": "target_flow",
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
    if not isinstance(res_data, dict):
        return res_data
    clean = res_data.copy()
    forbidden_keys = [
        "zis_template_version",
        "resources",
        "name",
        "description",
        "type",
        "properties",
    ]
    for key in forbidden_keys:
        if key in clean:
            del clean[key]
    return clean


# [HELPER] Sanitize Step Data (Specific for Flows)


def sanitize_step(step_data):
    keys_to_fix = {
        "next": "Next",
        "actionname": "ActionName",
        "parameters": "Parameters",
        "default": "Default",
        "choices": "Choices",
        "type": "Type",
        "end": "End",
        "resultpath": "ResultPath",
        "seconds": "Seconds",
    }
    existing_keys = list(step_data.keys())
    for k in existing_keys:
        k_lower = k.lower()
        if k_lower in keys_to_fix:
            target = keys_to_fix[k_lower]
            if k != target:
                val = step_data[k]
                if target not in step_data:
                    step_data[target] = val
                del step_data[k]


# [HELPER] Get the most relevant flow to display (for Trace/Debugger)


def get_flow_to_render(specific_key=None):
    if specific_key:
        res = st.session_state["bundle_resources"].get(specific_key)
        # Robust access
        r_type = get_zis_key(res, "type", "")
        if res and r_type == "ZIS::Flow":
            props = res.get("properties", {})
            return props.get("definition", {}), specific_key

    for k, v in st.session_state["bundle_resources"].items():
        r_type = get_zis_key(v, "type", "")
        if r_type == "ZIS::Flow":
            props = v.get("properties", {})
            return props.get("definition", {}), k

    return None, None


# [CRITICAL] Sync Function - TARGETED


def try_sync_from_editor(target_resource_key, new_content=None, force_ui_update=False):
    content = (
        new_content
        if new_content is not None
        else st.session_state.get("editor_content", "")
    )
    last_synced = st.session_state.get("last_synced_code", None)
    should_process = force_ui_update or (content != last_synced)

    if not target_resource_key:
        return True, None
    if not should_process:
        return True, None

    if not content or not content.strip():
        curr_res = st.session_state["bundle_resources"].get(target_resource_key, {})
        def_content = curr_res.get("properties", {}).get("definition", {})
        content = json.dumps(def_content, indent=2)
        st.session_state["editor_content"] = content
        st.session_state["last_synced_code"] = content
        return False, "Editor Empty."

    try:
        cleaned_content = clean_json_string(content)
        js = json.loads(cleaned_content)

        if "properties" in js and "definition" in js["properties"]:
            js = js["properties"]["definition"]
        elif "definition" in js:
            js = js["definition"]

        norm_js = normalize_zis_keys(clean_resource_definition(js))

        if target_resource_key in st.session_state["bundle_resources"]:
            st.session_state["bundle_resources"][target_resource_key]["properties"][
                "definition"
            ] = norm_js

        st.session_state["last_synced_code"] = content
        st.session_state["ui_render_key"] += 1

        if force_ui_update:
            formatted_json = json.dumps(norm_js, indent=2)
            st.session_state["editor_content"] = formatted_json
            st.session_state["last_synced_code"] = formatted_json
            st.session_state["editor_key"] += 1
        return True, None
    except json.JSONDecodeError as e:
        return False, f"JSON Error at line {e.lineno}: {e.msg}"
    except Exception as e:
        return False, str(e)


# ==========================================
# 1. THEME & CONFIG
# ==========================================
st.set_page_config(page_title="ZIS Studio", layout="wide", page_icon="⚡")

st.markdown(
    """
<style>
    header {visibility: hidden;}
    .block-container { padding-top: 1rem; padding-bottom: 2rem; }
    [data-testid="stSidebar"] { display: none; }
    [data-testid="collapsedControl"] { display: none; }
</style>
""",
    unsafe_allow_html=True,
)

# [STATE INITIALIZATION]
if "bundle_resources" not in st.session_state:
    st.session_state["bundle_resources"] = {
        "my_flow": {
            "type": "ZIS::Flow",
            "properties": {
                "name": "my_flow",
                "definition": {
                    "StartAt": "StartStep",
                    "States": {"StartStep": {"Type": "Pass", "End": True}},
                },
            },
        },
        "my_action": {
            "type": "ZIS::Action::Http",
            "properties": {
                "name": "my_action",
                "definition": {
                    "url": "https://httpbin.org/post",
                    "method": "POST",
                    "headers": [{"key": "Content-Type", "value": "application/json"}],
                    "requestBody": {"info": "Hello from ZIS"},
                },
            },
        },
        "my_job_spec": {
            "type": "ZIS::JobSpec",
            "properties": {
                "name": "my_job_spec",
                "definition": {
                    "event_source": "support",
                    "event_type": "ticket.created",
                    "target_flow": "zis:integration:default:my_flow",
                },
            },
        },
    }

# Ensure selection keys exist
all_keys = list(st.session_state["bundle_resources"].keys())
# Find flow keys for robust debug selection
flow_keys = [
    k
    for k, v in st.session_state["bundle_resources"].items()
    if get_zis_key(v, "type") == "ZIS::Flow"
]

if "res_selection_code" not in st.session_state:
    st.session_state["res_selection_code"] = all_keys[0] if all_keys else None

if "res_selection_vis" not in st.session_state:
    st.session_state["res_selection_vis"] = all_keys[0] if all_keys else None

if "res_selection_deb" not in st.session_state:
    # Prefer Flow, then any, then None
    st.session_state["res_selection_deb"] = (
        flow_keys[0] if flow_keys else (all_keys[0] if all_keys else None)
    )

if "editor_key" not in st.session_state:
    st.session_state["editor_key"] = 0
if "ui_render_key" not in st.session_state:
    st.session_state["ui_render_key"] = 0

curr_code_key = st.session_state.get("res_selection_code")
if (
    curr_code_key
    and "editor_content" not in st.session_state
    and curr_code_key in st.session_state["bundle_resources"]
):
    curr_res = st.session_state["bundle_resources"][curr_code_key]
    curr_def = curr_res.get("properties", {}).get("definition", {})
    content = json.dumps(curr_def, indent=2)
    st.session_state["editor_content"] = content
    st.session_state["last_synced_code"] = content

if "cached_svg" not in st.session_state:
    st.session_state["cached_svg"] = None
if "cached_svg_hash" not in st.session_state:
    st.session_state["cached_svg_hash"] = ""

for key in ["zd_subdomain", "zd_email", "zd_token", "zis_oauth_token"]:
    if key not in st.session_state:
        st.session_state[key] = ""

if "zis_configs" not in st.session_state:
    st.session_state["zis_configs"] = {}
if "current_integration_name" not in st.session_state:
    st.session_state["current_integration_name"] = ""
if "code_edit_mode" not in st.session_state:
    st.session_state["code_edit_mode"] = "Bundle Resource"
if "cfg_editor_key" not in st.session_state:
    st.session_state["cfg_editor_key"] = 0


# ==========================================
# 3. HELPERS & STATIC SVG RENDERER
# ==========================================


def get_auth():
    return (
        HTTPBasicAuth(f"{st.session_state.zd_email}/token", st.session_state.zd_token)
        if st.session_state.zd_token
        else None
    )


def get_base_url():
    sub = st.session_state.zd_subdomain
    return f"https://{sub}.zendesk.com/api/services/zis/registry" if sub else ""


def get_configs_url(integration):
    sub = st.session_state.zd_subdomain
    return (
        f"https://{sub}.zendesk.com/api/services/zis/integrations/{integration}/configs"
        if sub
        else ""
    )


def get_configs_headers():
    """Return auth headers for the Configs API (requires OAuth token, not API token)."""
    token = st.session_state.get("zis_oauth_token", "")
    if token:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    return {"Content-Type": "application/json"}


def detect_config_scopes():
    """Scan all ZIS::Flow resources and return unique LoadConfig scope values."""
    scopes = []
    for res in st.session_state.get("bundle_resources", {}).values():
        if get_zis_key(res, "type", "") != "ZIS::Flow":
            continue
        definition = res.get("properties", {}).get("definition", {})
        states = definition.get("States", {})
        for state in states.values():
            action = get_zis_key(state, "ActionName", "") or state.get("ActionName", "")
            if "LoadConfig" in action:
                scope = state.get("Parameters", {}).get("scope") or state.get(
                    "parameters", {}
                ).get("scope")
                if scope and scope not in scopes:
                    scopes.append(scope)
    return scopes


def test_connection():
    try:
        r = requests.get(
            f"https://{st.session_state.zd_subdomain}.zendesk.com/api/v2/users/me.json",
            auth=get_auth(),
            timeout=10,
        )
        return (
            (True, "Active")
            if r.status_code == 200
            else (
                False,
                f"Error {r.status_code}",
            )
        )
    except Exception as e:
        return False, f"{str(e)}"


# [NEW] CACHED SVG RENDERER - CONTENT HASH BASED


def render_flow_static_svg(
    flow_def, highlight_path=None, selected_step=None, key_suffix="default"
):
    if not HAS_GRAPHVIZ:
        return st.warning(
            "Graphviz not installed. Please add 'graphviz' to requirements.txt"
        )

    content_sig = (
        json.dumps(flow_def, sort_keys=True) + str(highlight_path) + str(selected_step)
    )
    current_hash = hashlib.md5(content_sig.encode()).hexdigest()

    if (
        st.session_state["cached_svg"] is None
        or st.session_state["cached_svg_hash"] != current_hash
    ):
        try:
            dot = graphviz.Digraph(format="svg")
            dot.attr(rankdir="TB", splines="polyline", compound="true")
            dot.attr(nodesep="0.6", ranksep="0.8")
            dot.attr(
                "node",
                shape="box",
                style="filled,rounded",
                fillcolor="#ECECFF",
                color="#939393",
                penwidth="2",
                fontname="Arial",
                fontsize="12",
                margin="0.2",
            )
            dot.attr("edge", color="#666666", penwidth="1.5", arrowsize="0.7")

            states = get_zis_key(flow_def, "States", {})
            start_step = get_zis_key(flow_def, "StartAt")

            dot.node(
                "START",
                "Start",
                shape="circle",
                fillcolor="#4CAF50",
                color="#388E3C",
                width="0.6",
                fontcolor="white",
                id="node_START",
                fontsize="10",
            )
            dot.node(
                "END",
                "End",
                shape="doublecircle",
                fillcolor="#333333",
                color="#000000",
                width="0.5",
                fontcolor="white",
                id="node_END",
                fontsize="10",
            )

            sorted_items = sorted(states.items())

            for k, v in sorted_items:
                sType = get_zis_key(v, "Type", "Unknown")
                display_k = k if len(k) < 25 else k[:23] + ".."
                label = f"{display_k}\n[{sType}]"
                safe_id = re.sub(r"[^a-zA-Z0-9]", "_", k)
                dot.node(k, label, id=f"node_{safe_id}")

            if start_step:
                dot.edge("START", start_step)

            for k, v in sorted_items:
                # 1. Normal Next
                next_step = get_zis_key(v, "Next")
                if next_step:
                    dot.edge(k, next_step)

                # 2. Choice Default
                default_step = get_zis_key(v, "Default")
                if default_step:
                    dot.edge(
                        k,
                        default_step,
                        label="Default",
                        fontsize="10",
                        fontcolor="#666666",
                    )

                # 3. Choice Rules
                choices = get_zis_key(v, "Choices", [])
                for c in choices:
                    c_next = get_zis_key(c, "Next")
                    if c_next:
                        dot.edge(
                            k, c_next, label="Match", fontsize="10", fontcolor="#666666"
                        )

                # 4. Catch Errors
                catch_list = get_zis_key(v, "Catch", [])
                if isinstance(catch_list, list):
                    for c in catch_list:
                        c_next = get_zis_key(c, "Next")
                        if c_next:
                            dot.edge(
                                k,
                                c_next,
                                label="Catch Error",
                                style="dashed",
                                fontsize="10",
                                fontcolor="#D32F2F",
                                color="#D32F2F",
                            )

                # 5. Terminals
                sType = get_zis_key(v, "Type", "Unknown")
                is_explicit_end = get_zis_key(v, "End", False)
                is_terminal = sType in ["Succeed", "Fail"]
                if is_explicit_end or is_terminal:
                    dot.edge(k, "END")

            svg_bytes = dot.pipe()
            svg_str = svg_bytes.decode("utf-8")
            svg_str = re.sub(r"<\?xml.*?>", "", svg_str)
            svg_str = re.sub(r"<!DOCTYPE.*?>", "", svg_str)

            st.session_state["cached_svg"] = svg_str
            st.session_state["cached_svg_hash"] = current_hash

        except Exception as e:
            st.error(f"Render Error: {e}")
            return

    final_svg = st.session_state["cached_svg"]

    css_rules = []
    if selected_step:
        safe_sel_id = re.sub(r"[^a-zA-Z0-9]", "_", selected_step)
        css_rules.append(
            f"""
            #node_{safe_sel_id} polygon, #node_{safe_sel_id} path, #node_{safe_sel_id} ellipse {{
                fill: #FFF59D !important;
                stroke: #FBC02D !important;
                stroke-width: 3px !important;
            }}
        """
        )

    if highlight_path:
        for step in highlight_path:
            safe_step_id = re.sub(r"[^a-zA-Z0-9]", "_", step)
            if step == selected_step:
                continue
            css_rules.append(
                f"""
                #node_{safe_step_id} polygon, #node_{safe_step_id} path, #node_{safe_step_id} ellipse {{
                    fill: #C8E6C9 !important;
                    stroke: #4CAF50 !important;
                }}
            """
            )

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
        {"".join(css_rules)}
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


def handle_resource_change_code(widget_key, selection_state_key):
    new_value = st.session_state[widget_key]
    st.session_state[selection_state_key] = new_value

    res_map = st.session_state["bundle_resources"]
    if new_value in res_map:
        new_def = res_map[new_value]["properties"]["definition"]
        formatted_json = json.dumps(new_def, indent=2)
        st.session_state["editor_content"] = formatted_json
        st.session_state["last_synced_code"] = formatted_json
        st.session_state["editor_key"] += 1


def handle_resource_change_generic(widget_key, selection_state_key):
    new_value = st.session_state[widget_key]
    st.session_state[selection_state_key] = new_value

    if "vis" in selection_state_key:
        st.session_state["cached_svg"] = None
    if "deb" in selection_state_key:
        if "debug_res" in st.session_state:
            del st.session_state["debug_res"]


def render_resource_manager(location_key, selection_state_key, allowed_types=None):
    with st.container(border=True):
        st.markdown("**🗂️ Resource Manager**")

        res_map = st.session_state["bundle_resources"]

        if allowed_types:
            res_keys = [
                k for k, v in res_map.items() if get_zis_key(v, "type") in allowed_types
            ]
        else:
            res_keys = list(res_map.keys())

        current_selection = st.session_state.get(selection_state_key)

        # [FIX] Auto-correct selection if invalid for current view
        if not res_keys:
            st.warning("No matching resources.")
            selected_key = None
            if current_selection is not None:
                st.session_state[selection_state_key] = None
        elif current_selection not in res_keys:
            # Snap to first item and refresh
            st.session_state[selection_state_key] = res_keys[0]
            current_selection = res_keys[0]
            force_refresh()

        col_sel, col_type, col_act = st.columns([3, 1, 1])

        with col_sel:
            if res_keys:
                widget_key = f"res_sel_{location_key}"

                # [CRITICAL FIX] Ensure session state is initialized for the widget
                if widget_key not in st.session_state:
                    st.session_state[widget_key] = current_selection

                if "code" in selection_state_key:
                    cb = handle_resource_change_code
                else:
                    cb = handle_resource_change_generic

                # [CRITICAL FIX] Removed 'index=curr_idx'. The widget relies on st.session_state[widget_key].
                selected_key = st.selectbox(
                    "Select File",
                    res_keys,
                    key=widget_key,
                    on_change=cb,
                    args=(widget_key, selection_state_key),
                )
            else:
                selected_key = None

        if selected_key:
            current_res = res_map.get(selected_key)
            if current_res:
                current_type = get_zis_key(current_res, "type", "Unknown")

                with col_type:
                    st.write("")
                    st.info(f"**{current_type.replace('ZIS::', '')}**")

                with col_act:
                    st.write("")
                    st.write("")
                    if len(list(res_map.keys())) > 1:
                        if st.button(
                            "🗑️ Del", type="secondary", key=f"del_{location_key}"
                        ):
                            del st.session_state["bundle_resources"][selected_key]

                            rem_keys = list(st.session_state["bundle_resources"].keys())
                            if rem_keys:
                                st.session_state[selection_state_key] = rem_keys[0]
                                # Also update widget state to prevent stale
                                # selection error
                                st.session_state[f"res_sel_{location_key}"] = rem_keys[
                                    0
                                ]
                            else:
                                st.session_state[selection_state_key] = None
                                st.session_state[f"res_sel_{location_key}"] = None

                            if "code" in selection_state_key:
                                if rem_keys:
                                    handle_resource_change_code(
                                        widget_key, selection_state_key
                                    )
                                else:
                                    st.session_state["editor_content"] = ""

                            force_refresh()
                    else:
                        st.caption("Locked")

        if not allowed_types:
            with st.expander("➕ Add New Resource"):
                c_new_1, c_new_2, c_new_3 = st.columns([2, 2, 1])
                with c_new_1:
                    new_res_name = st.text_input("Name", key=f"nrn_{location_key}")
                with c_new_2:
                    new_res_type = st.selectbox(
                        "Type",
                        ["ZIS::Flow", "ZIS::Action::Http", "ZIS::JobSpec"],
                        key=f"nrt_{location_key}",
                    )
                with c_new_3:
                    st.write("")
                    st.write("")
                    if st.button("Create", key=f"btn_create_{location_key}"):
                        safe_name = new_res_name.lower().strip().replace(" ", "_")
                        if safe_name and safe_name not in res_map:
                            def_def = {}
                            if new_res_type == "ZIS::Flow":
                                def_def = {
                                    "StartAt": "StartStep",
                                    "States": {
                                        "StartStep": {"Type": "Pass", "End": True}
                                    },
                                }
                            elif new_res_type == "ZIS::Action::Http":
                                def_def = {"url": "https://", "method": "GET"}
                            elif new_res_type == "ZIS::JobSpec":
                                def_def = {
                                    "event_source": "zendesk",
                                    "event_type": "ticket.saved",
                                    "target_flow": "",
                                }

                            st.session_state["bundle_resources"][safe_name] = {
                                "type": new_res_type,
                                "properties": {
                                    "name": safe_name,
                                    "definition": def_def,
                                },
                            }
                            st.session_state[selection_state_key] = safe_name
                            # Update widget state to match new creation
                            st.session_state[f"res_sel_{location_key}"] = safe_name

                            if "code" in selection_state_key:
                                formatted_json = json.dumps(def_def, indent=2)
                                st.session_state["editor_content"] = formatted_json

                            st.success(f"Created: {safe_name}")
                            time.sleep(0.5)
                            force_refresh()
                        else:
                            st.error("Invalid or duplicate name")


# ==========================================
# 5. MAIN PAGE
# ==========================================
st.title("ZIS Studio")

t_set, t_imp, t_code, t_vis, t_dep, t_deb = st.tabs(
    [
        "⚙️ Settings",
        "📥 Import",
        "📝 Code Editor",
        "🎨 Visual Designer",
        "🚀 Deploy",
        "🐞 Debugger",
    ]
)

with t_set:
    st.markdown("### 🔑 Zendesk Credentials")
    c1, c2 = st.columns([1, 1])
    with c1:
        with st.container(border=True):
            st.text_input("Subdomain", key="zd_subdomain")
            st.text_input("Email", key="zd_email")
            st.text_input("API Token", key="zd_token", type="password")
            st.divider()
            st.caption("Optional: Required to read/update ZIS:Config")
            st.text_input(
                "ZIS OAuth Token",
                key="zis_oauth_token",
                type="password",
                help=(
                    "Only required to fetch or push Integration Configs. "
                    "The standard API Token cannot be used for that endpoint."
                ),
            )
            if st.button("Connect"):
                ok, msg = test_connection()
                if ok:
                    st.session_state["is_connected"] = True
                    st.toast(f"API Token: {msg}", icon="✅")
                else:
                    st.toast(f"API Token: {msg}", icon="❌")

                oauth_token = st.session_state.get("zis_oauth_token", "")
                if oauth_token:
                    try:
                        sub = st.session_state.zd_subdomain
                        r = requests.get(
                            f"https://{sub}.zendesk.com/api/v2/users/me.json",
                            headers={"Authorization": f"Bearer {oauth_token}"},
                            timeout=10,
                        )
                        if r.status_code == 200:
                            st.toast("OAuth Token: Active", icon="✅")
                        else:
                            st.toast(f"OAuth Token: Error {r.status_code}", icon="❌")
                    except Exception as e:
                        st.toast(f"OAuth Token: {e}", icon="❌")
    with c2:
        if st.session_state.get("is_connected"):
            st.success(f"✅ Connected to: **{st.session_state.zd_subdomain}**")

with t_imp:
    st.markdown("### 🔎 Import Bundle")
    if not st.session_state.get("is_connected"):
        st.warning("Configure Settings first.")
    else:
        st.info("This will overwrite your current workspace with the imported bundle.")
        if st.button("🚀 Start Deep Scan"):
            try:
                with st.status(
                    "🔍 Scanning Zendesk Integrations...", expanded=True
                ) as status:
                    status.write("Fetching Integrations list...")
                    try:
                        resp = requests.get(
                            f"{get_base_url()}/integrations",
                            auth=get_auth(),
                            timeout=15,
                        )
                    except Exception as e:
                        status.update(label="Connection Failed", state="error")
                        st.error(f"Network Error: {e}")
                        resp = None

                    if resp and resp.status_code == 200:
                        ints = resp.json().get("integrations", [])
                        total_ints = len(ints)
                        status.write(
                            f"Found {total_ints} integrations. Scanning bundles..."
                        )
                        progress_bar = status.progress(0)

                        res = []
                        for idx, i in enumerate(ints):
                            nm = i["name"]
                            progress = (idx + 1) / total_ints
                            progress_bar.progress(progress)
                            try:
                                b_resp = requests.get(
                                    f"{get_base_url()}/{nm}/bundles",
                                    auth=get_auth(),
                                    timeout=5,
                                )
                                if b_resp.status_code == 200:
                                    bundles = b_resp.json().get("bundles", [])
                                    for b in bundles:
                                        res.append(
                                            {
                                                "int": nm,
                                                "bun": b["name"],
                                                "uuid": b.get("uuid", ""),
                                            }
                                        )
                            except BaseException:
                                pass
                        st.session_state["scan_results"] = res
                        status.update(
                            label=f"Found {len(res)} bundles.",
                            state="complete",
                            expanded=False,
                        )
                    elif resp:
                        st.error(f"API Error: {resp.status_code} - {resp.text}")
            except Exception as e:
                st.error(str(e))

        if "scan_results" in st.session_state:
            res = st.session_state["scan_results"]
            if not res:
                st.warning("No bundles found.")
            else:
                sel = st.selectbox(
                    "Bundles",
                    range(len(res)),
                    format_func=lambda i: f"{res[i]['int']} / {res[i]['bun']}",
                )
                if st.button("Load Bundle"):
                    it = res[sel]
                    url = f"{get_base_url()}/{it['int']}/bundles/{it['uuid'] or it['bun']}"
                    try:
                        r = requests.get(url, auth=get_auth(), timeout=10)
                        if r.status_code == 200:
                            imported_resources = r.json().get("resources", {})
                            new_bundle_map = {}

                            for res_key, res_data in imported_resources.items():
                                r_type = get_zis_key(res_data, "type", "Unknown")
                                r_props = res_data.get("properties", {})

                                if r_type == "ZIS::JobSpec":
                                    # Zendesk API stores JobSpec fields directly in
                                    # properties (no definition key) — normalize to
                                    # internal format
                                    r_def = {
                                        "event_source": r_props.pop("event_source", ""),
                                        "event_type": r_props.pop("event_type", ""),
                                        "target_flow": r_props.pop(
                                            "flow_name", r_props.pop("target_flow", "")
                                        ),
                                    }
                                    r_props["definition"] = r_def
                                else:
                                    r_def = r_props.get("definition", {})
                                    clean_def = normalize_zis_keys(
                                        clean_resource_definition(r_def)
                                    )
                                    if r_type == "ZIS::Action::Http" and isinstance(
                                        clean_def, dict
                                    ):
                                        hdrs = clean_def.get("headers", [])
                                        if isinstance(hdrs, dict):
                                            clean_def["headers"] = [
                                                {"key": k, "value": v}
                                                for k, v in hdrs.items()
                                            ]
                                    r_props["definition"] = clean_def

                                res_data["properties"] = r_props
                                new_bundle_map[res_key] = res_data

                            if new_bundle_map:
                                st.session_state["bundle_resources"] = new_bundle_map

                                flows = [
                                    k
                                    for k, v in new_bundle_map.items()
                                    if get_zis_key(v, "type") == "ZIS::Flow"
                                ]
                                primary_key = (
                                    flows[0]
                                    if flows
                                    else list(new_bundle_map.keys())[0]
                                )

                                st.session_state["res_selection_code"] = primary_key
                                st.session_state["res_selection_vis"] = primary_key
                                st.session_state["res_selection_deb"] = primary_key

                                # [FIX] Force widget state sync
                                st.session_state["res_sel_code_tab"] = primary_key
                                st.session_state["res_sel_vis_tab"] = primary_key
                                st.session_state["res_sel_deb_tab"] = primary_key

                                formatted_js = json.dumps(
                                    new_bundle_map[primary_key]["properties"][
                                        "definition"
                                    ],
                                    indent=2,
                                )
                                st.session_state["editor_content"] = formatted_js
                                st.session_state["last_synced_code"] = formatted_js
                                st.session_state["editor_key"] += 1

                                st.session_state["current_bundle_name"] = it["bun"]
                                st.session_state["current_integration_name"] = it["int"]

                                # Fetch configs for this integration
                                try:
                                    cfg_resp = requests.get(
                                        get_configs_url(it["int"]),
                                        params={"filter[scope]": "*"},
                                        headers=get_configs_headers(),
                                        timeout=10,
                                    )
                                    if cfg_resp.status_code == 200:
                                        configs_list = cfg_resp.json().get(
                                            "configs", []
                                        )
                                        merged = {}
                                        for c in configs_list:
                                            merged.update(c.get("config", {}))
                                        st.session_state["zis_configs"] = merged
                                        st.session_state["cfg_editor_key"] += 1
                                        if configs_list:
                                            st.toast(
                                                f"Loaded {len(configs_list)} config(s)",
                                                icon="🔧",
                                            )
                                except Exception:
                                    pass  # configs are optional

                                st.toast("Bundle Loaded!", icon="🎉")
                                time.sleep(0.5)
                                force_refresh()
                            else:
                                st.warning("Bundle is empty.")
                        else:
                            st.error(f"Failed to load bundle: {r.status_code}")
                    except Exception as e:
                        st.error(f"Network error: {e}")

with t_code:
    edit_mode = st.radio(
        "Editing",
        ["Bundle Resource", "Integration Configs"],
        index=0 if st.session_state["code_edit_mode"] == "Bundle Resource" else 1,
        horizontal=True,
        key="code_edit_mode_radio",
        label_visibility="collapsed",
    )
    st.session_state["code_edit_mode"] = edit_mode

    st.divider()

    if edit_mode == "Integration Configs":
        st.caption(
            "Edit configs as JSON — save locally here, then push to Zendesk from the Deploy tab."
        )

        # Bump editor key when switching to this mode so editor re-initializes with current content
        if st.session_state.get("_prev_code_edit_mode") != "Integration Configs":
            st.session_state["cfg_editor_key"] += 1
        st.session_state["_prev_code_edit_mode"] = "Integration Configs"

        # Fetch row
        detected_scopes = detect_config_scopes()
        fc1, fc2 = st.columns([3, 1])
        with fc1:
            _cfg_int = st.text_input(
                "Integration name",
                value=st.session_state.get("current_integration_name", ""),
                key="cfg_editor_int_name",
                label_visibility="collapsed",
                placeholder="Integration name (e.g. my_integration)",
            )
            if detected_scopes:
                st.caption(
                    "Scopes detected in flows: "
                    + "  ".join(f"`{s}`" for s in detected_scopes)
                )
        with fc2:
            if st.button("Fetch Configs", key="btn_cfg_fetch_editor"):
                _ready = st.session_state.get("is_connected") and bool(
                    st.session_state.get("zis_oauth_token")
                )
                if not _ready:
                    st.warning("Connect and add a ZIS OAuth Token in Settings first.")
                elif not _cfg_int:
                    st.warning("Enter an integration name.")
                else:
                    try:
                        r = requests.get(
                            get_configs_url(_cfg_int),
                            params={"filter[scope]": "*"},
                            headers=get_configs_headers(),
                            timeout=10,
                        )
                        if r.status_code == 200:
                            configs_list = r.json().get("configs", [])
                            configs_by_scope = {}
                            for c in configs_list:
                                configs_by_scope[c.get("scope", "unknown")] = (
                                    c.get("config", {})
                                )
                            st.session_state["zis_configs"] = configs_by_scope
                            st.session_state["current_integration_name"] = _cfg_int
                            st.session_state["cfg_editor_key"] += 1
                            st.toast(
                                f"Fetched {len(configs_list)} scope(s)", icon="✅"
                            )
                            st.rerun()
                        else:
                            st.error(f"API Error {r.status_code}: {r.text}")
                    except Exception as e:
                        st.error(str(e))

        # Load configs JSON into editor when switching to this mode
        configs_content = json.dumps(st.session_state.get("zis_configs", {}), indent=2)
        cfg_editor_key = f"cfg_editor_{st.session_state['cfg_editor_key']}"

        if not st.session_state.get("zis_configs"):
            st.info("No configs loaded. Enter the integration name and click **Fetch Configs**.")

        if HAS_EDITOR:
            custom_buttons = [
                {
                    "name": "Save",
                    "feather": "Save",
                    "primary": True,
                    "hasText": True,
                    "alwaysOn": True,
                    "commands": ["submit"],
                    "style": {"top": "0.46rem", "right": "0.4rem"},
                }
            ]

            cfg_resp = code_editor(
                configs_content,
                lang="json",
                height=600,
                key=cfg_editor_key,
                buttons=custom_buttons,
                options={
                    "showLineNumbers": True,
                    "wrap": True,
                    "autoClosingBrackets": True,
                },
            )

            if cfg_resp and cfg_resp.get("type") == "submit":
                try:
                    parsed = json.loads(clean_json_string(cfg_resp.get("text", "{}")))
                    if isinstance(parsed, dict):
                        st.session_state["zis_configs"] = parsed
                        st.toast("Configs saved!", icon="✅")
                    else:
                        st.error("❌ Configs must be a JSON object (key-value pairs).")
                except json.JSONDecodeError as e:
                    st.error(f"❌ JSON Error at line {e.lineno}: {e.msg}")

    else:
        st.session_state["_prev_code_edit_mode"] = "Bundle Resource"
        render_resource_manager("code_tab", "res_selection_code")
        st.divider()

        target_key = st.session_state.get("res_selection_code")

        if target_key and st.session_state.get("editor_content") == "":
            res_obj = st.session_state["bundle_resources"].get(target_key)
            if res_obj:
                curr_def = res_obj.get("properties", {}).get("definition", {})
                content = json.dumps(curr_def, indent=2)
                st.session_state["editor_content"] = content
                st.session_state["editor_key"] += 1

        dk = f"code_editor_{st.session_state['editor_key']}"
        if HAS_EDITOR:
            custom_buttons = [
                {
                    "name": "Save",
                    "feather": "Save",
                    "primary": True,
                    "hasText": True,
                    "alwaysOn": True,
                    "commands": ["submit"],
                    "style": {"top": "0.46rem", "right": "0.4rem"},
                }
            ]

            resp = code_editor(
                st.session_state.get("editor_content", ""),
                lang="json",
                height=600,
                key=dk,
                buttons=custom_buttons,
                options={
                    "showLineNumbers": True,
                    "wrap": True,
                    "autoClosingBrackets": True,
                },
            )

            if resp and resp.get("text") and resp.get("type") != "submit":
                st.session_state["editor_content"] = resp["text"]

            if resp and resp.get("type") == "submit":
                current_text = resp.get("text", "")
                st.session_state["editor_content"] = current_text
                target_key = st.session_state.get("res_selection_code")
                ok, err = try_sync_from_editor(
                    target_key, new_content=current_text, force_ui_update=False
                )
                if ok:
                    st.toast("Saved Successfully!", icon="✅")
                else:
                    st.error(f"❌ Syntax Error: {err}")

with t_vis:
    render_resource_manager("vis_tab", "res_selection_vis")
    st.divider()

    current_sel_key = st.session_state.get("res_selection_vis")
    current_res_obj = st.session_state["bundle_resources"].get(current_sel_key)

    if st.session_state.get("res_selection_code") == current_sel_key:
        ok, err = try_sync_from_editor(current_sel_key, force_ui_update=False)
        if not ok:
            st.error(f"⚠️ Invalid JSON in Code Editor: {err}")

    flow_to_show_def, flow_to_show_name = get_flow_to_render(current_sel_key)
    ui_key = st.session_state["ui_render_key"]

    # [FIX] Initialize variables strictly before conditional blocks
    sel = None
    current_type = None

    main_c1, main_c2 = st.columns([1, 1])

    if current_res_obj:
        current_type = get_zis_key(current_res_obj, "type", "Unknown")
        current_def = current_res_obj.get("properties", {}).get("definition", {})

        with main_c1:
            if current_type == "ZIS::Flow":
                states = get_zis_key(current_def, "States", {})
                keys = list(states.keys())

                st.subheader("Flow Steps")
                sel = st.selectbox(
                    "Step", ["(Select)"] + keys, key=f"step_selector_{ui_key}"
                )

                with st.expander("➕ Add Step"):
                    nn = st.text_input("Name")
                    nt = st.selectbox(
                        "Type", ["Action", "Choice", "Wait", "Pass", "Succeed", "Fail"]
                    )
                    if st.button("Add"):
                        states[nn] = (
                            {"Type": nt, "End": True} if nt == "Pass" else {"Type": nt}
                        )
                        current_def["States"] = states
                        if (
                            st.session_state.get("res_selection_code")
                            == current_sel_key
                        ):
                            formatted = json.dumps(current_def, indent=2)
                            st.session_state["editor_content"] = formatted
                            st.session_state["last_synced_code"] = formatted
                            st.session_state["editor_key"] += 1
                        st.session_state["ui_render_key"] += 1
                        force_refresh()

                st.divider()
                if sel and sel != "(Select)" and sel in states:
                    s_dat = states[sel]
                    sanitize_step(s_dat)
                    s_typ = get_zis_key(s_dat, "Type")
                    st.markdown(f"### {sel} `[{s_typ}]`")
                    if s_typ not in ["Succeed", "Fail", "Choice"]:
                        is_end = st.checkbox(
                            "End Flow?",
                            get_zis_key(s_dat, "End", False),
                            key=f"end_{sel}_{ui_key}",
                        )
                        if is_end:
                            s_dat["End"] = True
                            s_dat.pop("Next", None)
                        else:
                            s_dat.pop("End", None)
                            nxt_opts = [k for k in keys if k != sel]
                            curr_nxt = get_zis_key(s_dat, "Next", "")
                            idx = find_best_match_index(nxt_opts, curr_nxt)
                            final_idx = (idx + 1) if idx != -1 else 0
                            new_nxt = st.selectbox(
                                "Next",
                                ["(Select)"] + nxt_opts,
                                index=final_idx,
                                key=f"nxt_{sel}_{ui_key}",
                            )
                            if new_nxt != "(Select)":
                                s_dat["Next"] = new_nxt

                    if s_typ == "Action":
                        s_dat["ActionName"] = st.text_input(
                            "Action",
                            get_zis_key(s_dat, "ActionName", ""),
                            key=f"act_{sel}_{ui_key}",
                        )
                        current_params = get_zis_key(s_dat, "Parameters", {})
                        param_str = json.dumps(current_params, indent=2)
                        new_param_str = st.text_area(
                            "Params", param_str, key=f"prm_{sel}_{ui_key}"
                        )
                        try:
                            s_dat["Parameters"] = json.loads(new_param_str)
                        except BaseException:
                            st.caption("❌ Invalid JSON in Params")
                        s_dat["ResultPath"] = st.text_input(
                            "ResultPath (e.g. $.myVar)",
                            get_zis_key(s_dat, "ResultPath", ""),
                            key=f"res_{sel}_{ui_key}",
                        )

                    elif s_typ == "Choice":
                        idx_def = find_best_match_index(
                            [k for k in keys if k != sel], get_zis_key(s_dat, "Default")
                        )
                        final_idx_def = idx_def if idx_def != -1 else 0
                        s_dat["Default"] = st.selectbox(
                            "Default",
                            [k for k in keys if k != sel],
                            index=final_idx_def,
                            key=f"def_{sel}_{ui_key}",
                        )
                        chs = get_zis_key(s_dat, "Choices", [])
                        if not isinstance(chs, list):
                            chs = []
                        s_dat["Choices"] = chs
                        for i, ch in enumerate(chs):
                            with st.expander(f"Rule {i + 1}"):
                                ch["Variable"] = st.text_input(
                                    "Var",
                                    get_zis_key(ch, "Variable", ""),
                                    key=f"cv_{i}_{sel}_{ui_key}",
                                )

                                # [UPDATED] Full Operator List
                                ops = [
                                    "StringEquals",
                                    "StringMatches",
                                    "StringLessThan",
                                    "StringLessThanEquals",
                                    "StringGreaterThan",
                                    "StringGreaterThanEquals",
                                    "BooleanEquals",
                                    "NumericEquals",
                                    "NumericGreaterThan",
                                    "NumericGreaterThanEquals",
                                    "NumericLessThan",
                                    "NumericLessThanEquals",
                                    "IsPresent",
                                    "IsNull",
                                    "TimestampEquals",
                                    "TimestampLessThan",
                                    "TimestampLessThanEquals",
                                    "TimestampGreaterThan",
                                    "TimestampGreaterThanEquals",
                                ]

                                curr_op = "StringEquals"
                                curr_val = ""
                                for op in ops:
                                    val = get_zis_key(ch, op)
                                    if val is not None:
                                        curr_op = op
                                        curr_val = val
                                        break

                                new_op = st.selectbox(
                                    "Op",
                                    ops,
                                    index=ops.index(curr_op),
                                    key=f"cop_{i}_{sel}_{ui_key}",
                                )
                                new_val = st.text_input(
                                    "Val (True/False for bool)",
                                    str(curr_val),
                                    key=f"cqv_{i}_{sel}_{ui_key}",
                                )

                                for op in ops:
                                    ch.pop(op, None)
                                    ch.pop(op.lower(), None)

                                # Basic Type Inference for Save
                                real_val = new_val
                                if "Numeric" in new_op:
                                    try:
                                        real_val = float(new_val)
                                    except BaseException:
                                        pass
                                elif new_op in ["BooleanEquals", "IsPresent", "IsNull"]:
                                    real_val = new_val.lower() == "true"

                                ch[new_op] = real_val

                                idx_rule_next = find_best_match_index(
                                    [k for k in keys if k != sel],
                                    get_zis_key(ch, "Next"),
                                )
                                final_idx_rule = (
                                    idx_rule_next if idx_rule_next != -1 else 0
                                )

                                next_opts = [k for k in keys if k != sel]
                                ch["Next"] = st.selectbox(
                                    "GoTo",
                                    next_opts,
                                    index=final_idx_rule,
                                    key=f"cn_{i}_{sel}_{ui_key}",
                                )
                                if st.button("Del", key=f"cd_{i}_{sel}_{ui_key}"):
                                    chs.pop(i)
                                    force_refresh()
                        if st.button("Add Rule", key=f"ar_{sel}_{ui_key}"):
                            chs.append(
                                {"Variable": "$.", "StringEquals": "", "Next": ""}
                            )
                            force_refresh()

                    if st.button(
                        "Save Changes", type="primary", key=f"sv_{sel}_{ui_key}"
                    ):
                        if (
                            st.session_state.get("res_selection_code")
                            == current_sel_key
                        ):
                            new_code = json.dumps(current_def, indent=2)
                            st.session_state["editor_content"] = new_code
                            st.session_state["last_synced_code"] = new_code
                            st.session_state["editor_key"] += 1
                        st.success("Saved")
                        force_refresh()

            elif current_type == "ZIS::Action::Http":
                st.info("🎨 Action Designer")
                c1, c2 = st.columns(2)
                with c1:
                    current_def["method"] = st.selectbox(
                        "Method",
                        ["GET", "POST", "PUT", "DELETE", "PATCH"],
                        index=["GET", "POST", "PUT", "DELETE", "PATCH"].index(
                            current_def.get("method", "GET")
                        ),
                        key=f"mth_{ui_key}",
                    )
                    current_def["url"] = st.text_input(
                        "URL", value=current_def.get("url", ""), key=f"url_{ui_key}"
                    )

                st.subheader("Headers")
                hdrs = current_def.get("headers", [])
                if not isinstance(hdrs, list):
                    hdrs = []
                for i, h in enumerate(hdrs):
                    hc1, hc2 = st.columns(2)
                    h["key"] = hc1.text_input(
                        f"Key #{i}", h.get("key", ""), key=f"hk_{i}_{ui_key}"
                    )
                    h["value"] = hc2.text_input(
                        f"Value #{i}", h.get("value", ""), key=f"hv_{i}_{ui_key}"
                    )
                if st.button("Add Header"):
                    hdrs.append({"key": "", "value": ""})
                    current_def["headers"] = hdrs
                    force_refresh()

                if st.button("Save Action", type="primary"):
                    if st.session_state.get("res_selection_code") == current_sel_key:
                        new_code = json.dumps(current_def, indent=2)
                        st.session_state["editor_content"] = new_code
                        st.session_state["last_synced_code"] = new_code
                    st.success("Saved Action")

            elif current_type == "ZIS::JobSpec":
                st.info("🎨 Job Spec Configuration")
                current_def["event_source"] = st.text_input(
                    "Event Source",
                    current_def.get("event_source", "zendesk"),
                    key=f"es_{ui_key}",
                )
                current_def["event_type"] = st.text_input(
                    "Event Type",
                    current_def.get("event_type", "ticket.saved"),
                    key=f"et_{ui_key}",
                )
                current_def["target_flow"] = st.text_input(
                    "Target Flow Name (zis:integration:default:flow_name)",
                    current_def.get("target_flow", ""),
                    key=f"tf_{ui_key}",
                )

                if st.button("Save Job Spec", type="primary"):
                    if st.session_state.get("res_selection_code") == current_sel_key:
                        new_code = json.dumps(current_def, indent=2)
                        st.session_state["editor_content"] = new_code
                        st.session_state["last_synced_code"] = new_code
                    st.success("Saved Job Spec")
            else:
                st.warning(f"Visual Designer not available for {current_type}")

    with main_c2:
        if flow_to_show_def:
            st.markdown(f"**Viewing Flow: `{flow_to_show_name}`**")
            # [CRITICAL FIX] Safe access logic
            step_to_highlight = (
                sel
                if (current_type == "ZIS::Flow" and sel and sel != "(Select)")
                else None
            )
            render_flow_static_svg(
                flow_to_show_def, selected_step=step_to_highlight, key_suffix="vis"
            )
        else:
            st.info("No Flows found in this bundle.")

with t_dep:
    if not st.session_state.get("is_connected"):
        st.warning("Connect in Settings first.")
    else:
        st.markdown("### 🚀 Deploy Bundle")
        sub = st.session_state.get("zd_subdomain", "sub")
        default_int = f"zis_playground_{(sub or 'sub').lower().strip()}"
        with st.container(border=True):
            raw_int_name = st.text_input("Target Integration Name", value=default_int)
            target_int = raw_int_name.lower().strip().replace(" ", "_")
            bun_name = st.text_input(
                "Bundle Name",
                value=st.session_state.get("current_bundle_name", "my_bundle"),
            )

            if st.button("Deploy Bundle", type="primary"):
                with st.status("Deploying...") as status:
                    try:
                        status.write("Creating integration...")
                        requests.post(
                            f"{get_base_url()}/integrations",
                            auth=get_auth(),
                            json={"name": target_int, "display_name": target_int},
                            headers={"Content-Type": "application/json"},
                            timeout=10,
                        )

                        safe_bun = (
                            (bun_name or "")
                            .lower()
                            .strip()
                            .replace("-", "_")
                            .replace(" ", "")
                        )

                        resources_payload = {}
                        res_map = st.session_state["bundle_resources"]

                        for r_key, r_val in res_map.items():
                            r_copy = copy.deepcopy(r_val)
                            r_type = get_zis_key(r_copy, "type", "")
                            if r_type == "ZIS::JobSpec":
                                # Zendesk API expects JobSpec fields directly in
                                # properties (no definition key)
                                props = r_copy.get("properties", {})
                                def_fields = props.pop("definition", {})
                                props["event_source"] = def_fields.get(
                                    "event_source", ""
                                )
                                props["event_type"] = def_fields.get("event_type", "")
                                props["flow_name"] = def_fields.get(
                                    "target_flow", def_fields.get("flow_name", "")
                                )
                                r_copy["properties"] = props
                            else:
                                def_clean = clean_resource_definition(
                                    r_copy.get("properties", {}).get("definition", {})
                                )
                                r_copy["properties"]["definition"] = def_clean
                            resources_payload[r_key] = r_copy

                        payload = {
                            "zis_template_version": "2019-10-14",
                            "name": safe_bun,
                            "resources": resources_payload,
                        }

                        status.write(f"Uploading {len(resources_payload)} resources...")
                        r = requests.post(
                            f"{get_base_url()}/{target_int}/bundles",
                            auth=get_auth(),
                            json=payload,
                            headers={"Content-Type": "application/json"},
                            timeout=15,
                        )

                        if r.status_code in [200, 201]:
                            # Push configs if any are stored
                            configs_to_push = st.session_state.get("zis_configs", {})
                            if configs_to_push:
                                status.write(
                                    f"Pushing {len(configs_to_push)} config scope(s)..."
                                )
                                try:
                                    for cfg_scope, cfg_data in configs_to_push.items():
                                        cr = requests.put(
                                            f"{get_configs_url(target_int)}/{cfg_scope}",
                                            json={"config": cfg_data},
                                            headers=get_configs_headers(),
                                            timeout=10,
                                        )
                                        if cr.status_code == 404:
                                            requests.post(
                                                get_configs_url(target_int),
                                                json={
                                                    "scope": cfg_scope,
                                                    "config": cfg_data,
                                                },
                                                headers=get_configs_headers(),
                                                timeout=10,
                                            )
                                except Exception:
                                    pass

                            st.balloons()
                            status.update(label="Deployed!", state="complete")
                            st.success(f"Deployed {safe_bun} to {target_int}")
                            st.json(payload)
                        else:
                            status.update(label="Failed", state="error")
                            st.error(r.text)
                    except Exception as e:
                        st.error(str(e))

        st.divider()
        st.markdown("### 🔧 Push Configs")
        st.caption(
            "Push locally stored configs to Zendesk. Requires a ZIS OAuth Token in Settings."
        )
        _dep_cfg_int = st.text_input(
            "Integration Name",
            value=st.session_state.get("current_integration_name", ""),
            key="dep_cfg_int",
        )
        if st.button("Push Configs to Zendesk", key="btn_dep_cfg_push"):
            _dep_ready = st.session_state.get("is_connected") and bool(
                st.session_state.get("zis_oauth_token")
            )
            if not _dep_ready:
                st.warning("Connect and add a ZIS OAuth Token in Settings first.")
            elif not _dep_cfg_int:
                st.warning("Enter an integration name.")
            else:
                _dep_configs = st.session_state.get("zis_configs", {})
                if not _dep_configs:
                    st.info("No configs to push. Load them in the Code Editor first.")
                else:
                    try:
                        push_errors = []
                        push_ok = 0
                        for scope, scope_cfg in _dep_configs.items():
                            r = requests.put(
                                f"{get_configs_url(_dep_cfg_int)}/{scope}",
                                json={"config": scope_cfg},
                                headers=get_configs_headers(),
                                timeout=10,
                            )
                            if r.status_code == 404:
                                r = requests.post(
                                    get_configs_url(_dep_cfg_int),
                                    json={"scope": scope, "config": scope_cfg},
                                    headers=get_configs_headers(),
                                    timeout=10,
                                )
                            if r.status_code in [200, 201]:
                                push_ok += 1
                            else:
                                push_errors.append(
                                    f"`{scope}`: {r.status_code} - {r.text}"
                                )
                        if push_errors:
                            st.error("\n\n".join(push_errors))
                        else:
                            st.toast(f"Pushed {push_ok} config scope(s)", icon="✅")
                    except Exception as e:
                        st.error(str(e))


with t_deb:
    render_resource_manager("deb_tab", "res_selection_deb", allowed_types=["ZIS::Flow"])
    st.divider()

    current_sel_key = st.session_state.get("res_selection_deb")
    current_res_obj = st.session_state["bundle_resources"].get(current_sel_key)

    # [FIX] Auto-Sync changes from Editor if debugging the same file
    if st.session_state.get("res_selection_code") == current_sel_key:
        ok, err = try_sync_from_editor(current_sel_key, force_ui_update=False)
        if not ok:
            st.error(f"⚠️ Invalid JSON in Code Editor: {err}")

    if current_res_obj:
        current_type = get_zis_key(current_res_obj, "type", "Unknown")
        current_def = current_res_obj.get("properties", {}).get("definition", {})

        st.info(f"Currently Debugging: **{current_sel_key}**")

        if current_type == "ZIS::Flow":
            col_input, col_graph = st.columns([1, 1])
            with col_input:
                st.markdown("### Flow Simulation")
                inp = st.text_area(
                    "JSON Input",
                    '{"ticket": {"id": 123}}',
                    height=200,
                    key="debug_input",
                )
                if st.button("▶️ Run Simulation", type="primary"):
                    try:
                        input_json = json.loads(inp)
                        eng = ZISFlowEngine(
                            normalize_zis_keys(current_def),
                            input_json,
                            {},
                            st.session_state.get("zis_configs", {}),
                        )
                        logs, ctx, path = eng.run()
                        st.session_state["debug_res"] = (logs, ctx, path)
                    except json.JSONDecodeError:
                        st.error("Invalid JSON input for simulation.")
                    except Exception as e:
                        st.error(f"Simulation Error: {e}")

                st.divider()
                if "debug_res" in st.session_state:
                    logs, ctx, path = st.session_state["debug_res"]
                    with st.expander("Logs"):
                        for log in logs:
                            st.text(log)
                    with st.expander("Context"):
                        st.json(ctx)
            with col_graph:
                st.markdown("### Trace")
                current_path = (
                    st.session_state["debug_res"][2]
                    if "debug_res" in st.session_state
                    else None
                )
                render_flow_static_svg(current_def, current_path, key_suffix="debug")
        else:
            st.warning("Please select a **ZIS::Flow** resource.")
    else:
        st.warning("No resource selected.")
