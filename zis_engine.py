import time
import requests
import re
from jsonpath_ng import parse

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
        self.visited_states = []  # [NEW] Track the path

    def log(self, step, message, status="INFO"):
        entry = f"[{time.strftime('%H:%M:%S')}] {step}: {message} ({status})"
        self.logs.append(entry)

    def resolve_path(self, path, data):
        """Resolves JSONPath like $.input.ticket.id"""
        if not isinstance(path, str) or not path.startswith("$."):
            return path
        try:
            jsonpath_expr = parse(path.replace("$.", ""))
            matches = jsonpath_expr.find(data)
            return matches[0].value if matches else None
        except:
            return None

    def interpolate(self, text):
        """Replaces {{$.value}} with actual data"""
        if not isinstance(text, str): return text
        placeholders = re.findall(r'\{\{(.*?)\}\}', text)
        for ph in placeholders:
            val = self.resolve_path(ph, self.context)
            text = text.replace(f"{{{{{ph}}}}}", str(val))
        return text

    def run_action(self, state_name, state_def):
        """Simulates the 'Action' state (HTTP Requests)"""
        action_name = state_def.get("ActionName", "Unknown Action")
        params = state_def.get("Parameters", {})
        
        resolved_params = {}
        for k, v in params.items():
            key = k[:-2] if k.endswith(".$") else k
            val = self.resolve_path(v, self.context) if k.endswith(".$") else self.interpolate(v)
            resolved_params[key] = val

        self.log(state_name, f"Executing Action: {action_name}", "RUNNING")
        
        # --- LOCAL MOCKING LOGIC ---
        url = resolved_params.get("url", "")
        method = resolved_params.get("method", "GET")
        
        if url:
            try:
                response = requests.request(method, url, json=resolved_params.get("body"))
                self.log(state_name, f"API Hit: {url} [{response.status_code}]", "SUCCESS")
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
        # Handle wrapped definition or raw definition
        flow_def = self.flow.get("definition", self.flow)
        current_state_name = flow_def.get("StartAt")
        states = flow_def.get("States", {})
        
        self.log("START", f"Starting Flow: {self.context.get('flow_name', 'Local')}")

        steps_run = 0
        MAX_STEPS = 50 

        while current_state_name and steps_run < MAX_STEPS:
            steps_run += 1
            
            # [NEW] Record the path
            self.visited_states.append(current_state_name)
            
            state = states.get(current_state_name)
            if not state:
                self.log("ERROR", f"State {current_state_name} not found", "FAIL")
                break

            state_type = state.get("Type")
            
            if state_type == "Action":
                result = self.run_action(current_state_name, state)
                if "ResultPath" in state and result is not None:
                    clean_key = state["ResultPath"].split(".")[-1]
                    self.context[clean_key] = result
                current_state_name = state.get("Next")

            elif state_type == "Choice":
                choices = state.get("Choices", [])
                next_state = state.get("Default")
                matched = False
                for rule in choices:
                    variable = self.resolve_path(rule.get("Variable"), self.context)
                    if "StringEquals" in rule:
                        if str(variable) == str(rule["StringEquals"]):
                            next_state = rule["Next"]
                            matched = True
                            self.log(current_state_name, f"Match! {variable} == {rule['StringEquals']}", "INFO")
                            break
                    elif "NumericEquals" in rule:
                        try:
                            if float(variable) == float(rule["NumericEquals"]):
                                next_state = rule["Next"]
                                matched = True
                                self.log(current_state_name, f"Match! {variable} == {rule['NumericEquals']}", "INFO")
                                break
                        except: pass

                if not matched:
                    self.log(current_state_name, "No rules matched. Taking Default path.", "INFO")
                current_state_name = next_state

            elif state_type == "Pass":
                self.log(current_state_name, "Passing through")
                if "Result" in state and "ResultPath" in state:
                    clean_key = state["ResultPath"].split(".")[-1]
                    self.context[clean_key] = state["Result"]
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
            self.log("SYSTEM", "Max steps reached", "WARNING")
            
        # [NEW] Return visited_states as the 3rd value
        return self.logs, self.context, self.visited_states