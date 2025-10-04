import streamlit as st
import json
import os
import subprocess
import tempfile
from pathlib import Path

# --- Page Configuration ---
st.set_page_config(layout="wide", page_title="InfraWare Dashboard")

# --- Helper Function to run your CLI ---
def run_infraware_command(command, *args):
    """Runs an infraware command and returns the JSON output."""
    try:
        # --- FIX: Set environment variable to ensure UTF-8 encoding ---
        # This prevents UnicodeEncodeError on Windows when emojis are printed
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"

        # We construct the command just like you would in the terminal
        full_command = ["infraware", command] + list(args)
        result = subprocess.run(
            full_command, 
            capture_output=True, 
            text=True, 
            check=True, 
            encoding='utf-8', # Explicitly set encoding for output
            env=env
        )
        # Handle cases where the CLI might print text before the JSON
        # by finding the first '{' which marks the start of the JSON object.
        json_start_index = result.stdout.find('{')
        if json_start_index == -1:
            st.error("No JSON object found in the CLI output.")
            return None
        
        json_output = result.stdout[json_start_index:]
        return json.loads(json_output)

    except FileNotFoundError:
        st.error("Error: `infraware` command not found. Did you run `pip install -e .`?")
        return None
    except subprocess.CalledProcessError as e:
        st.error(f"An error occurred: {e.stderr}")
        return None
    except json.JSONDecodeError:
        st.error("Could not parse the JSON output from the CLI. Make sure the command supports --output json.")
        return None

# --- Sidebar for Navigation ---
st.sidebar.title("InfraWare Menu")
app_mode = st.sidebar.selectbox(
    "Choose a tool to use",
    ["Security Scan", "Cost Analysis"]
)

# --- Main App UI ---
st.title(f"🛡️ InfraWare Dashboard: {app_mode}")

# --- Security Scan Page ---
if app_mode == "Security Scan":
    st.write("Upload your Terraform plan file and a custom rules file (optional) to scan for vulnerabilities.")

    plan_file = st.file_uploader("1. Upload your `tfplan.json` file", type=["json"])
    rules_file = st.file_uploader("2. Upload your custom rules file (optional)", type=["yaml", "yml"])

    if st.button("Run Security Scan") and plan_file is not None:
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".json", prefix="plan_") as tmp_plan:
            tmp_plan.write(plan_file.getvalue().decode("utf-8"))
            temp_plan_path = tmp_plan.name

        rules_dir_to_use = "rules" # Default rules directory
        temp_rules_dir = None

        # If a user uploads a custom rules file, we create a temporary directory for it
        if rules_file is not None:
            temp_rules_dir = tempfile.TemporaryDirectory()
            rules_dir_to_use = temp_rules_dir.name
            with open(os.path.join(rules_dir_to_use, rules_file.name), "wb") as tmp_rule:
                tmp_rule.write(rules_file.getvalue())
            st.info(f"Using custom rules from `{rules_file.name}`.")
        else:
            st.info("No custom rules uploaded. Using default rules directory.")

        with st.spinner("Scanning for vulnerabilities..."):
            # --- FIX: The command name is '--output', not '--format' ---
            scan_results = run_infraware_command(
                "scan",
                temp_plan_path,
                "--rules-dir", rules_dir_to_use,
                "--format", "json"
            )
            
            # --- FIX: Parse the new, richer JSON structure ---
            if scan_results is not None:
                summary = scan_results.get("summary", {})
                vulnerabilities = scan_results.get("vulnerabilities", [])
                
                total_vulns = summary.get("total_vulnerabilities", 0)
                risk_score = summary.get("risk_score", "N/A")

                st.write(f"**Scan Complete! Found {total_vulns} vulnerabilities with a risk score of {risk_score}.**")
                
                # Display the detailed list of vulnerabilities
                st.dataframe(vulnerabilities)

        # Clean up temporary files and directories
        os.unlink(temp_plan_path)
        if temp_rules_dir:
            temp_rules_dir.cleanup()

# --- Cost Analysis Page ---
elif app_mode == "Cost Analysis":
    st.write("Upload your Terraform plan file to estimate resource costs.")

    plan_file = st.file_uploader("Upload your `tfplan.json` file", type=["json"])

    if st.button("Run Cost Analysis") and plan_file is not None:
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".json", prefix="plan_") as tmp_plan:
            tmp_plan.write(plan_file.getvalue().decode("utf-8"))
            temp_plan_path = tmp_plan.name

        with st.spinner("Analyzing costs..."):
            cost_results = run_infraware_command(
                "cost",
                "analysis",
                temp_plan_path,
                "--pricing-file", "pricing.yaml",
                "--format", "json"
            )
            
            if cost_results is not None:
                total_cost = cost_results.get("summary", {}).get("total_monthly_cost", 0)
                st.write(f"**Analysis Complete! Estimated Monthly Cost: ${total_cost:.2f}**")
                st.dataframe(cost_results.get("resources", []))

        # Clean up the temporary file
        os.unlink(temp_plan_path)

