import json
import yaml
import sys

def scan_plan(plan_file_path, rule_file_path):
    print(f"Scanning Terraform plan {plan_file_path} with rules from {rule_file_path}...\n")

    # 1. Load and parse the Terraform plan JSON file
    try:
        with open(plan_file_path, 'r') as f:
            plan_data = json.load(f)
    except Exception as e:
        print(f"Error reading plan file: {e}")
        return

    # 2. Load the YAML rules
    try:
        with open(rule_file_path, 'r') as f:
            rules = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading rule file: {e}")
        return

    # 3. The Scanning Engine for Plan JSON
    vulnerabilities_found = 0
    
    # The list of all resources is in 'planned_values' under 'root_module'
    resources = plan_data.get('planned_values', {}).get('root_module', {}).get('resources', [])
    
    for rule in rules:
        for resource in resources:
            # Check if the resource type in the plan matches the rule
            if resource.get('type') == rule['resource']:
                # The resource's attributes are in the 'values' dictionary
                attributes = resource.get('values', {})
                if rule['attribute'] in attributes and attributes[rule['attribute']] == rule['value']:
                    print("--- VULNERABILITY FOUND! ---")
                    print(f"  Rule ID: {rule['id']}")
                    print(f"  Severity: {rule['severity']}")
                    print(f"  Description: {rule['description']}")
                    print(f"  In Resource: {resource.get('type')} ({resource.get('name')})\n")
                    vulnerabilities_found += 1

    if vulnerabilities_found == 0:
        print("No vulnerabilities found. Good job!")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python -m infraqube.main <path_to_plan.json> <path_to_rule_file>")
        sys.exit(1)
    
    plan_file = sys.argv[1]
    rule_file = sys.argv[2]
    scan_plan(plan_file, rule_file)