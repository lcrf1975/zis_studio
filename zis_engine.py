import time
import requests
import re
import copy
from jsonpath_ng import parse

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
        Fixes the issue where context keys were being overwritten at the root.
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
        
        # Default behavior: InputPath=$ (pass all), OutputPath=$ (pass all)
        if path is None: 
            return current_data
            
        if path == "$":
            return current_data
            
        return self.resolve_path(path, current_data)

    def run_action(self, state_name, state_def):
        """Simulates the 'Action' state (HTTP Requests)"""
        action_name = state_def.get("ActionName", "Unknown Action")
        params = state_def.get("Parameters", {})
        
        resolved_params = {}
        for k, v in params.items():
            # Handle .$ suffix for dynamic parameters
            key = k[:-2] if k.endswith(".$") else k
            if k.endswith(".$"):
                val = self.resolve_path(v, self.context)
            else:
                val = self.interpolate(v)
            resolved_params[key] = val

        self.log(state_name, f"Executing Action: {action_name}", "RUNNING")
        
        url = resolved_params.get("url", "")
        method = resolved_params.get("method", "GET")
        
        # Handle body/payload
        # ZIS often sends 'body' param as the JSON payload
        payload = resolved_params.get("body")
        
        if url:
            try:
                # Basic auth simulation if headers present
                headers = resolved_params.get("headers", {})
                
                response = requests.request(method, url, json=payload, headers=headers)
                status_msg = f"API Hit: {url} [{response.status_code}]"
                
                if response.status_code >= 400:
                    self.log(state_name, status_msg, "ERROR")
                else:
                    self.log(state_name, status_msg, "SUCCESS")
                    
                return response.json() if response.content else {}
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

            # 1. Apply InputPath (Filter data entering the state)
            # input_data = self.apply_io_path(state, self.context, is_input=True) 
            # Note: For simplicity in this engine, we keep self.context global, 
            # but in real ZIS, InputPath limits what "Parameters" can see. 
            
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
                    variable = self.resolve_path(rule.get("Variable"), self.context)
                    
                    # [UPDATE] Extended Logic Support for Comparisons
                    try:
                        if "StringEquals" in rule and str(variable) == str(rule["StringEquals"]):
                            matched = True
                        elif "BooleanEquals" in rule and bool(variable) == bool(rule["BooleanEquals"]):
                            matched = True
                        elif "NumericEquals" in rule and float(variable) == float(rule["NumericEquals"]):
                            matched = True
                        elif "NumericGreaterThan" in rule and float(variable) > float(rule["NumericGreaterThan"]):
                            matched = True
                        elif "NumericGreaterThanEquals" in rule and float(variable) >= float(rule["NumericGreaterThanEquals"]):
                            matched = True
                        elif "NumericLessThan" in rule and float(variable) < float(rule["NumericLessThan"]):
                            matched = True
                        elif "NumericLessThanEquals" in rule and float(variable) <= float(rule["NumericLessThanEquals"]):
                            matched = True
                    except:
                        # Fallback for type conversion errors
                        pass
                    
                    if matched:
                        next_state = rule["Next"]
                        self.log(current_state_name, f"Rule Matched: {rule.get('Variable')}", "INFO")
                        break

                if not matched:
                    self.log(current_state_name, "No rules matched. Defaulting.", "INFO")
                current_state_name = next_state

            elif state_type == "Pass":
                self.log(current_state_name, "Passing through")
                if "Result" in state:
                    result = state["Result"]
                    # If ResultPath is present, map Result to it
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
            
            # 2. Apply OutputPath (Filter data leaving the state - Not fully impl in this mock)
            
            if state.get("End"):
                self.log(current_state_name, "End of Flow reached")
                break
        
        if steps_run >= MAX_STEPS:
            self.log("SYSTEM", "Max steps reached (Loop detection)", "WARNING")
            
        return self.logs, self.context, self.visited_states