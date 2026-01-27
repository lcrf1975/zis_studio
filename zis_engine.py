import time
import requests
import re
import copy
import json
import fnmatch
from datetime import datetime
from jsonpath_ng import parse

class ZISActionTester:
    """
    Standalone runner for ZIS Actions (ZIS::Action::Http)
    Allows testing actions without running a full flow.
    """
    @staticmethod
    def execute(action_def, params_input):
        engine = ZISFlowEngine({}, {}, {}, {}) # Dummy engine for utility methods
        
        # Mock a state definition compatible with run_action
        mock_state_def = {
            "ActionName": "TestRunner",
            "Parameters": params_input
        }
        
        # Merge action definition props (url, method) with user input params
        combined_params = {**action_def, **params_input}
        mock_state_def["Parameters"] = combined_params

        return engine.run_action("TEST_ACTION", mock_state_def)

class ZISFlowEngine:
    def __init__(self, flow_definition, input_data, connections, configs):
        self.flow = flow_definition
        # Initialize context with standard ZIS structure
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
        """Resolves JSONPath like $.input.ticket.id"""
        if not isinstance(path, str) or not path.startswith("$."):
            return path
        try:
            # Handle root reference
            if path == "$": return data
            
            jsonpath_expr = parse(path.replace("$.", ""))
            matches = jsonpath_expr.find(data)
            return matches[0].value if matches else None
        except Exception as e:
            return None

    def set_nested_value(self, path, value):
        """
        Sets value at path like '$.ticket.user.id', creating intermediates.
        """
        if not path or not path.startswith("$."):
            return

        # Strip $. and split
        keys = path.replace("$.", "").split(".")
        current = self.context

        for i, key in enumerate(keys[:-1]):
            # Create dict if it doesn't exist or isn't a dict
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]

        # Set the final value
        current[keys[-1]] = value

    def interpolate(self, text):
        """Replaces {{$.value}} with actual data"""
        if not isinstance(text, str): return text
        placeholders = re.findall(r'\{\{(.*?)\}\}', text)
        for ph in placeholders:
            val = self.resolve_path(ph, self.context)
            text = text.replace(f"{{{{{ph}}}}}", str(val))
        return text

    def apply_io_path(self, state, current_data, is_input=True):
        """Handles InputPath and OutputPath filtering"""
        path_key = "InputPath" if is_input else "OutputPath"
        path = state.get(path_key)
        
        if path is None: return current_data
        if path == "$": return current_data
            
        return self.resolve_path(path, current_data)

    def run_action(self, state_name, state_def):
        """Simulates the 'Action' state (HTTP Requests)"""
        action_name = state_def.get("ActionName", "Unknown Action")
        params = state_def.get("Parameters", {})
        
        resolved_params = {}
        for k, v in params.items():
            key = k[:-2] if k.endswith(".$") else k
            if k.endswith(".$"):
                val = self.resolve_path(v, self.context)
            else:
                val = self.interpolate(v)
            resolved_params[key] = val

        self.log(state_name, f"Executing Action: {action_name}", "RUNNING")
        
        url = resolved_params.get("url", "")
        method = resolved_params.get("method", "GET")
        payload = resolved_params.get("body") or resolved_params.get("requestBody")
        
        if isinstance(payload, str):
            try: payload = json.loads(payload)
            except: pass

        if url:
            try:
                headers = resolved_params.get("headers", {})
                req_headers = {}
                if isinstance(headers, list):
                    for h in headers:
                        if "key" in h and "value" in h:
                            req_headers[h["key"]] = h["value"]
                elif isinstance(headers, dict):
                    req_headers = headers

                response = requests.request(method, url, json=payload, headers=req_headers)
                status_msg = f"API Hit: {url} [{response.status_code}]"
                
                try: resp_json = response.json()
                except: resp_json = {"raw_text": response.text}

                if response.status_code >= 400:
                    self.log(state_name, status_msg, "ERROR")
                    self.log(state_name, f"Resp: {str(resp_json)[:100]}...", "ERROR")
                else:
                    self.log(state_name, status_msg, "SUCCESS")
                    
                return resp_json
            except Exception as e:
                self.log(state_name, f"Request failed: {str(e)}", "ERROR")
                return {"error": str(e)}
        else:
            self.log(state_name, "No URL found. Simulating success (Mock Mode)", "WARNING")
            return {
                "mock_response": "Success", 
                "message": f"Simulated execution of {action_name}",
                "input_params": resolved_params
            }

    # [NEW] Recursive Rule Evaluator
    def evaluate_rule(self, rule, context):
        """
        Recursively evaluates ASL Choice rules including Logic (And/Or/Not)
        and Comparisons (String, Numeric, Timestamp, Boolean).
        """
        # 1. Handle Logical Operators (Recursive)
        if "And" in rule:
            return all(self.evaluate_rule(sub, context) for sub in rule["And"])
        if "Or" in rule:
            return any(self.evaluate_rule(sub, context) for sub in rule["Or"])
        if "Not" in rule:
            return not self.evaluate_rule(rule["Not"], context)

        # 2. Resolve Variable (Required for comparisons)
        var_path = rule.get("Variable")
        if not var_path: return False
            
        val = self.resolve_path(var_path, context)

        # 3. Existence Checks
        if "IsPresent" in rule:
            exists = val is not None
            # Handle string "true"/"false" if passed from basic UI
            target = rule["IsPresent"]
            if isinstance(target, str): target = target.lower() == "true"
            return exists if target else not exists
        if "IsNull" in rule:
            is_null = val is None
            target = rule["IsNull"]
            if isinstance(target, str): target = target.lower() == "true"
            return is_null if target else not is_null

        # 4. String Comparisons
        str_val = str(val) if val is not None else ""
        if "StringEquals" in rule:
            return str_val == str(rule["StringEquals"])
        if "StringLessThan" in rule:
            return str_val < str(rule["StringLessThan"])
        if "StringLessThanEquals" in rule:
            return str_val <= str(rule["StringLessThanEquals"])
        if "StringGreaterThan" in rule:
            return str_val > str(rule["StringGreaterThan"])
        if "StringGreaterThanEquals" in rule:
            return str_val >= str(rule["StringGreaterThanEquals"])
        if "StringMatches" in rule:
            return fnmatch.fnmatch(str_val, str(rule["StringMatches"]))

        # 5. Numeric Comparisons
        def safe_float(v):
            try: return float(v)
            except: return None

        num_val = safe_float(val)
        if num_val is not None:
            if "NumericEquals" in rule:
                return num_val == safe_float(rule["NumericEquals"])
            if "NumericLessThan" in rule:
                return num_val < safe_float(rule["NumericLessThan"])
            if "NumericLessThanEquals" in rule:
                return num_val <= safe_float(rule["NumericLessThanEquals"])
            if "NumericGreaterThan" in rule:
                return num_val > safe_float(rule["NumericGreaterThan"])
            if "NumericGreaterThanEquals" in rule:
                return num_val >= safe_float(rule["NumericGreaterThanEquals"])

        # 6. Boolean Comparisons
        if "BooleanEquals" in rule:
            target = rule["BooleanEquals"]
            if isinstance(target, str): target = target.lower() == "true"
            return bool(val) == bool(target)

        # 7. Timestamp Comparisons
        def safe_date(d):
            try: return datetime.fromisoformat(str(d).replace('Z', '+00:00'))
            except: return None

        dt_val = safe_date(val)
        if dt_val is not None:
            if "TimestampEquals" in rule:
                return dt_val == safe_date(rule["TimestampEquals"])
            if "TimestampLessThan" in rule:
                return dt_val < safe_date(rule["TimestampLessThan"])
            if "TimestampLessThanEquals" in rule:
                return dt_val <= safe_date(rule["TimestampLessThanEquals"])
            if "TimestampGreaterThan" in rule:
                return dt_val > safe_date(rule["TimestampGreaterThan"])
            if "TimestampGreaterThanEquals" in rule:
                return dt_val >= safe_date(rule["TimestampGreaterThanEquals"])

        return False

    def run(self):
        flow_def = self.flow.get("definition", self.flow)
        current_state_name = flow_def.get("StartAt")
        states = flow_def.get("States", {})
        
        self.log("START", f"Starting Flow: {self.context.get('flow_name', 'Local')}")

        steps_run = 0
        MAX_STEPS = 50 

        while current_state_name and steps_run < MAX_STEPS:
            steps_run += 1
            self.visited_states.append(current_state_name)
            
            state = states.get(current_state_name)
            if not state:
                self.log("ERROR", f"State {current_state_name} not found", "FAIL")
                break
            
            state_type = state.get("Type")
            result = None
            
            if state_type == "Action":
                result = self.run_action(current_state_name, state)
                if "ResultPath" in state:
                    self.set_nested_value(state["ResultPath"], result)
                current_state_name = state.get("Next")

            elif state_type == "Choice":
                choices = state.get("Choices", [])
                next_state = state.get("Default")
                matched = False
                
                for rule in choices:
                    # [UPDATED] Use recursive evaluator
                    if self.evaluate_rule(rule, self.context):
                        matched = True
                        next_state = rule.get("Next")
                        self.log(current_state_name, "Rule Matched", "INFO")
                        break

                if not matched:
                    self.log(current_state_name, "No rules matched. Defaulting.", "INFO")
                current_state_name = next_state

            elif state_type == "Pass":
                self.log(current_state_name, "Passing through")
                if "Result" in state:
                    result = state["Result"]
                    if "ResultPath" in state:
                        self.set_nested_value(state["ResultPath"], result)
                current_state_name = state.get("Next")

            elif state_type == "Wait":
                seconds = state.get("Seconds", 1)
                self.log(current_state_name, f"Waiting {seconds}s...", "SLEEP")
                time.sleep(float(seconds))
                current_state_name = state.get("Next")

            elif state_type == "Succeed":
                self.log(current_state_name, "Flow Succeeded", "SUCCESS")
                break
            elif state_type == "Fail":
                error = state.get("Error", "FailState")
                self.log(current_state_name, f"Flow Failed: {error}", "FAIL")
                break
            
            if state.get("End"):
                self.log(current_state_name, "End of Flow reached")
                break
        
        if steps_run >= MAX_STEPS:
            self.log("SYSTEM", "Max steps reached (Loop detection)", "WARNING")
            
        return self.logs, self.context, self.visited_states