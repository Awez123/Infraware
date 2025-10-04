from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.responses import HTMLResponse
import json
import tempfile
import os
import subprocess
from typing import List

# This is our FastAPI application
app = FastAPI(title="InfraWare Server")

# This is the path to our simple HTML frontend
HTML_FILE_PATH = os.path.join(os.path.dirname(__file__), "templates/index.html")

def run_infraware_command(command: List[str]):
    """A helper function to run infraware commands and handle JSON output."""
    try:
        # --- FIX: Set PYTHONUTF8=1 environment variable for the subprocess ---
        # This forces the child process to use UTF-8, solving emoji encoding errors on Windows.
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            env=env  # <-- Pass the modified environment to the subprocess
        )
        
        # Find the start of the JSON output
        json_start_index = result.stdout.find('{')
        if json_start_index == -1:
            json_start_index = result.stdout.find('[')
        
        if json_start_index != -1:
            try:
                return json.loads(result.stdout[json_start_index:])
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse JSON output. Error: {e}. Raw output: {result.stdout}")
        
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, command, output=result.stdout, stderr=result.stderr)
            
        raise ValueError("No JSON output found from CLI and command returned success.")

    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="'infraware' command not found. Is the package installed correctly?")
    except (subprocess.CalledProcessError, ValueError) as e:
        error_details = f"Failed to execute or parse command output. Error: {str(e)}"
        if isinstance(e, subprocess.CalledProcessError):
            # Include stderr in the error message for better debugging
            error_details += f" | Stderr: {e.stderr}"
        raise HTTPException(status_code=500, detail=error_details)


@app.post("/api/scan")
async def api_scan_plan(plan_file: UploadFile = File(...), rules_file: UploadFile = File(None)):
    """
    API endpoint that accepts a tfplan.json and optional rules file,
    runs the scan, and returns the results.
    """
    with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".json", encoding="utf-8") as tmp_plan:
        content = await plan_file.read()
        tmp_plan.write(content.decode("utf-8"))
        temp_plan_path = tmp_plan.name

    command = ["infraware", "scan", temp_plan_path, "--format", "json"]

    if rules_file:
        with tempfile.TemporaryDirectory() as temp_rules_dir:
            temp_rules_path = os.path.join(temp_rules_dir, rules_file.filename)
            with open(temp_rules_path, "wb") as f:
                f.write(await rules_file.read())
            
            command.extend(["--rules-dir", temp_rules_dir])
            scan_results = run_infraware_command(command)
    else:
        # Assuming default rules are in a 'rules' directory relative to where the server is run
        command.extend(["--rules-dir", "rules"])
        scan_results = run_infraware_command(command)
    
    os.unlink(temp_plan_path)
    
    return scan_results


@app.post("/api/cost")
async def api_cost_analysis(
    plan_file: UploadFile = File(...),
    region: str = Form(None),
    usage_hours: float = Form(730.0),
    # format is accepted but server forces JSON output for machine consumption
    output_format: str = Form("json")
):
    """
    API endpoint that accepts a tfplan.json (or other infrastructure file),
    runs the cost analysis and returns JSON results.
    """
    with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".json", encoding="utf-8") as tmp_plan:
        content = await plan_file.read()
        # write bytes decoded as utf-8; allow either text or bytes uploads
        try:
            tmp_plan.write(content.decode("utf-8"))
        except Exception:
            # fallback if already str-like
            tmp_plan.write(str(content))
        temp_plan_path = tmp_plan.name

    # First try to run cost analysis directly by importing the analyzer class
    try:
        # Importing the command module should not modify files in commands/.
        from infraware.commands.cost_analysis import CostAnalyzer

        analyzer = CostAnalyzer()
        # analyze_file_costs returns a plain dict suitable for JSON
        result = analyzer.analyze_file_costs(temp_plan_path, region, usage_hours)

        # Clean up temp file
        try:
            os.unlink(temp_plan_path)
        except Exception:
            pass

        return result

    except Exception:
        # Fallback to subprocess-based CLI invocation (keeps behavior consistent if import fails)
        command = ["infraware", "cost-analysis", temp_plan_path, "--format", "json", "--hours", str(usage_hours)]
        if region:
            command.extend(["--region", region])

        try:
            cost_results = run_infraware_command(command)
        finally:
            try:
                os.unlink(temp_plan_path)
            except Exception:
                pass

        return cost_results


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """
    This endpoint serves the main HTML page for our web UI.
    """
    with open(HTML_FILE_PATH, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)

