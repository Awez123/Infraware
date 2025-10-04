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


@app.post("/api/cve")
async def api_cve_action(
    action: str = Form(...),
    data_file: UploadFile = File(None),
    query: str = Form(None),
    # allow optional flags
    include_history: bool = Form(False),
):
    """
    API endpoint to run CVE related actions.
    action: one of 'update', 'bulk-download', 'search', 'stats'
    For 'search', provide 'query' (keywords or technology).
    For 'update' or 'bulk-download', no extra fields required; server will run the appropriate command.
    """
    # Prefer returning structured JSON for search/stats by calling CVEDatabase directly.
    if action == 'search':
        if not query:
            raise HTTPException(status_code=400, detail="Missing 'query' for cve-search action")
        import infraware.utils.cve_database as _cvedb_mod
        _DB = getattr(_cvedb_mod, 'CVEDatabase')

        def _search():
            db = _DB()
            cves = db.search_cves(query, None, 50)
            return [cve.to_dict() for cve in cves]

        import asyncio as _asyncio
        results = await _asyncio.to_thread(_search)
        return {"search_results": results}

    if action == 'stats':
        import infraware.utils.cve_database as _cvedb_mod
        _DB = getattr(_cvedb_mod, 'CVEDatabase')

        def _stats():
            db = _DB()
            return db.get_database_stats()

        import asyncio as _asyncio
        stats = await _asyncio.to_thread(_stats)
        return {"stats": stats}

    # Prefer calling command functions directly and capture their console output.
    import io
    import sys
    import contextlib
    import typer as _typer

    if action not in ("update", "bulk-download", "search", "stats"):
        raise HTTPException(status_code=400, detail=f"Unknown action: {action}")

    # Run the potentially-blocking command functions in a background thread
    import asyncio as _asyncio

    def _run_sync_action(act: str, qry: str):
        # This function runs on a worker thread and may call asyncio.run() safely.
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                if act == 'bulk-download':
                    original_confirm = _typer.confirm
                    try:
                        _typer.confirm = lambda *a, **k: True
                        from infraware.commands.cve_bulk_download import cve_bulk_download_cmd
                        cve_bulk_download_cmd()
                    finally:
                        _typer.confirm = original_confirm

                elif act == 'update':
                    from infraware.commands.cve_update import cve_update_cmd
                    cve_update_cmd()

                elif act == 'search':
                    from infraware.commands.cve_search import cve_search_cmd
                    if not qry:
                        # Raise a plain ValueError in the thread to be caught by the caller
                        raise ValueError("Missing 'query' for cve-search action")
                    # Call programmatically with explicit keyword args to avoid Typer OptionInfo defaults
                    cve_search_cmd(query=qry, severity=None, limit=10, output_format='table')

                elif act == 'stats':
                    from infraware.commands.cve_stats import cve_stats_cmd
                    cve_stats_cmd()

            return {"output": buf.getvalue()}

        except _typer.Exit as ex:
            return {"output": buf.getvalue(), "exit_code": getattr(ex, 'exit_code', 0)}

    try:
        result = await _asyncio.to_thread(_run_sync_action, action, query)
        # If thread returned a dict (output or exit code), just return it
        if isinstance(result, dict):
            return result
        # Otherwise, wrap as output
        return {"output": str(result)}

    except Exception:
        # Fall back to CLI subprocess if direct call fails or is inappropriate
        temp_path = None
        try:
            cmd = ["infraware"]
            if action == 'update':
                cmd.append('cve-update')
            elif action == 'bulk-download':
                cmd.append('cve-bulk-download')
                if include_history:
                    cmd.append('--history')
            elif action == 'search':
                cmd.extend(['cve-search'])
                if query:
                    cmd.append(query)
            elif action == 'stats':
                cmd.append('cve-stats')

            if data_file:
                with tempfile.NamedTemporaryFile(delete=False, mode='wb') as tf:
                    tf.write(await data_file.read())
                    temp_path = tf.name
                cmd.append(temp_path)

            # Run CLI and capture output JSON or text
            result = run_infraware_command(cmd)
            return result
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """
    This endpoint serves the main HTML page for our web UI.
    """
    with open(HTML_FILE_PATH, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)

