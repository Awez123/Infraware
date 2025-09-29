import hcl2
import yaml
import sys

def scan_file(terraform_file_path, rule_file_path):
    print(f"Scanning {terraform_file_path} with rules from {rule_file_path}...\n")

    # 1. Load and parse the Terraform file
    try:
        with open(terraform_file_path, 'r', encoding='utf-8') as f:
            tf_data = hcl2.load(f)
    except Exception as e:
        print(f"Error reading Terraform file: {e}")
        return

    # 2. Load the YAML rules
    try:
        with open(rule_file_path, 'r') as f:
            rules = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading rule file: {e}")
        return

    # 3. The Scanning Engine
    vulnerabilities_found = 0
    for rule in rules:
        resource_type = rule['resource']
        for resource in tf_data.get('resource', []):
            if resource_type in resource:
                # Get the dictionary of resources (e.g., {'my_bucket_1': {...}, 'my_bucket_2': {...}})
                resource_instances = resource[resource_type]
                
                # --- THIS IS THE CORRECTED LOGIC ---
                # We need to loop through the *values* (the attributes) of the instances, not their names.
                for instance_attributes in resource_instances.values():
                    if rule['attribute'] in instance_attributes and instance_attributes[rule['attribute']] == rule['value']:
                        print("--- VULNERABILITY FOUND! ---")
                        print(f"  Rule ID: {rule['id']}")
                        print(f"  Severity: {rule['severity']}")
                        print(f"  Description: {rule['description']}")
                        print(f"  In Resource: {resource_type}\n")
                        vulnerabilities_found += 1

    if vulnerabilities_found == 0:
        print("No vulnerabilities found. Good job!")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python -m infraqube.main <path_to_tf_file> <path_to_rule_file>")
        sys.exit(1)
    
    tf_file = sys.argv[1]
    rule_file = sys.argv[2]
    scan_file(tf_file, rule_file)