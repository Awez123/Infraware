from fastapi import FastAPI, File, UploadFile, HTTPException, Form, Request, Response, Depends
from fastapi.responses import HTMLResponse, StreamingResponse
import json
import tempfile
import os
import subprocess
from typing import List
import sqlite3
import hashlib
import logging
try:
    import bcrypt
except Exception:
    bcrypt = None
import secrets
import time
from datetime import datetime, timedelta

# This is our FastAPI application
app = FastAPI(title="InfraWare Server")

# This is the path to our simple HTML frontend
HTML_FILE_PATH = os.path.join(os.path.dirname(__file__), "templates/index.html")

# --- Simple SQLite-backed auth helpers ---
DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'infraware_auth.db')
SESSION_TTL = 3600

LOG = logging.getLogger("infraware.server")
LOG.setLevel(logging.INFO)


def _get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        expires_at INTEGER
    )''')
    conn.commit()
    conn.close()

    # If users table is empty, create an initial admin user with a random password and log it.
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('SELECT COUNT(1) as cnt FROM users')
    row = cur.fetchone()
    try:
        cnt = row['cnt'] if isinstance(row, dict) or hasattr(row, '__getitem__') else row[0]
    except Exception:
        cnt = 0
    if not cnt:
        # Create initial admin
        initial_password = secrets.token_urlsafe(12)
        if bcrypt:
            phash = bcrypt.hashpw(initial_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        else:
            phash = hashlib.sha256(initial_password.encode('utf-8')).hexdigest()
        conn.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)', ('admin', phash, 1))
        conn.commit()
        LOG.info(f"Created initial admin user 'admin' with password: {initial_password}")
        # Also write to a local file next to DB for operator retrieval (convenient during initial setup)
        try:
            info_path = DB_PATH + '.initial_admin.txt'
            with open(info_path, 'w', encoding='utf-8') as fh:
                fh.write(f"Initial admin username: admin\n")
                fh.write(f"Initial admin password: {initial_password}\n")
                fh.write(f"NOTE: Remove this file after retrieving the password.\n")
        except Exception:
            LOG.exception('Failed to write initial admin password file')
    conn.close()

init_db()

# In-memory token cache for quick lookups; persisted sessions are also stored in DB
_TOKEN_CACHE = {}

def _hash_password(password: str) -> str:
    """
    Hash a password. Use bcrypt when available. Returns the stored hash string.
    """
    if bcrypt:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def _create_user(username: str, password: str, is_admin: bool = False):
    conn = _get_conn()
    try:
        phash = _hash_password(password)
        conn.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)', (username, phash, 1 if is_admin else 0))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail='Username already exists')
    conn.close()

def _verify_user(username: str, password: str):
    conn = _get_conn()
    cur = conn.execute('SELECT id, password_hash, is_admin FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    stored = row['password_hash']
    # If bcrypt is available and stored hash indicates bcrypt (starts with $2b$ or $2y$), use bcrypt.checkpw
    try:
        if bcrypt and isinstance(stored, str) and stored.startswith('$2'):
            ok = bcrypt.checkpw(password.encode('utf-8'), stored.encode('utf-8'))
        else:
            # fallback: compare sha256
            ok = hashlib.sha256(password.encode('utf-8')).hexdigest() == stored
    except Exception:
        ok = False

    if ok:
        return {'id': row['id'], 'username': username, 'is_admin': bool(row['is_admin'])}
    return None

def _create_session(user_id: int, ttl_seconds: int = 3600):
    token = secrets.token_hex(32)
    expires_at = int(time.time()) + ttl_seconds
    conn = _get_conn()
    conn.execute('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)', (token, user_id, expires_at))
    conn.commit()
    conn.close()
    _TOKEN_CACHE[token] = {'user_id': user_id, 'expires_at': expires_at}
    return token

def _get_user_by_token(token: str):
    if not token:
        return None
    cached = _TOKEN_CACHE.get(token)
    now = int(time.time())
    if cached and cached['expires_at'] > now:
        # fetch user
        conn = _get_conn()
        cur = conn.execute('SELECT id, username, is_admin FROM users WHERE id = ?', (cached['user_id'],))
        row = cur.fetchone()
        conn.close()
        if row:
            return {'id': row['id'], 'username': row['username'], 'is_admin': bool(row['is_admin'])}

    # fall back to DB lookup
    conn = _get_conn()
    cur = conn.execute('SELECT user_id, expires_at FROM sessions WHERE token = ?', (token,))
    srow = cur.fetchone()
    if not srow:
        conn.close()
        return None
    if srow['expires_at'] < now:
        # expired
        conn.execute('DELETE FROM sessions WHERE token = ?', (token,))
        conn.commit()
        conn.close()
        _TOKEN_CACHE.pop(token, None)
        return None

    cur = conn.execute('SELECT id, username, is_admin FROM users WHERE id = ?', (srow['user_id'],))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    # cache
    _TOKEN_CACHE[token] = {'user_id': row['id'], 'expires_at': srow['expires_at']}
    return {'id': row['id'], 'username': row['username'], 'is_admin': bool(row['is_admin'])}

def _require_auth(request: Request):
    token = None
    # Accept token from Authorization: Bearer <token> or cookie 'infraware_token'
    auth = request.headers.get('authorization')
    if auth and auth.lower().startswith('bearer '):
        token = auth.split(None, 1)[1].strip()
    if not token:
        token = request.cookies.get('infraware_token')
    user = _get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail='Unauthorized')
    return user

def _require_admin(request: Request):
    user = _require_auth(request)
    if not user.get('is_admin'):
        raise HTTPException(status_code=403, detail='Admin privileges required')
    return user

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
async def api_scan_plan(request: Request, plan_file: UploadFile = File(...), rules_file: UploadFile = File(None)):
    """
    API endpoint that accepts a tfplan.json and optional rules file,
    runs the scan, and returns the results.
    """
    with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".json", encoding="utf-8") as tmp_plan:
        content = await plan_file.read()
        tmp_plan.write(content.decode("utf-8"))
        temp_plan_path = tmp_plan.name

    # require authenticated user
    _require_auth(request)

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


# --- Authentication endpoints ---
@app.post('/api/auth/register')
def api_register(username: str = Form(...), password: str = Form(...)):
    # create standard application user (non-admin)
    _create_user(username, password, is_admin=False)
    return {'status': 'ok', 'username': username}


@app.post('/api/auth/login')
def api_login(response: Response, username: str = Form(...), password: str = Form(...)):
    user = _verify_user(username, password)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid credentials')
    token = _create_session(user['id'], ttl_seconds=SESSION_TTL)
    # Set secure HttpOnly cookie so browsers include it automatically
    # Cookie expires in SESSION_TTL seconds
    # Use integer epoch seconds for expires to avoid timezone-aware datetime requirement
    expires_ts = int(time.time()) + SESSION_TTL
    response.set_cookie('infraware_token', token, httponly=True, secure=False, samesite='lax', expires=expires_ts)
    # return token only for non-browser clients; browsers will use cookie
    return {'token': token, 'user': {'id': user['id'], 'username': user['username'], 'is_admin': user['is_admin']}}


@app.post('/api/auth/logout')
@app.post('/api/auth/logout')
def api_logout(response: Response, token: str = Form(None), request: Request = None):
    # allow token in form or in Authorization header / cookie
    if not token and request:
        auth = request.headers.get('authorization')
        if auth and auth.lower().startswith('bearer '):
            token = auth.split(None, 1)[1].strip()
        if not token:
            token = request.cookies.get('infraware_token')
    if not token:
        raise HTTPException(status_code=400, detail='Missing token')
    conn = _get_conn()
    conn.execute('DELETE FROM sessions WHERE token = ?', (token,))
    conn.commit()
    conn.close()
    _TOKEN_CACHE.pop(token, None)
    # Clear cookie on logout
    response.delete_cookie('infraware_token')
    return {'status': 'ok'}


@app.post('/api/auth/create_user')
def api_create_user(username: str = Form(...), password: str = Form(...), is_admin: bool = Form(False), request: Request = None):
    # Admin-only endpoint to create users
    _require_admin(request)
    _create_user(username, password, is_admin=bool(is_admin))
    return {'status': 'ok', 'username': username, 'is_admin': bool(is_admin)}


@app.get('/api/auth/users')
def api_list_users(request: Request):
    """Admin-only: list all users (id, username, is_admin, created_at)."""
    _require_admin(request)
    conn = _get_conn()
    cur = conn.execute('SELECT id, username, is_admin, created_at FROM users ORDER BY id')
    rows = cur.fetchall()
    conn.close()
    users = []
    for r in rows:
        users.append({'id': r['id'], 'username': r['username'], 'is_admin': bool(r['is_admin']), 'created_at': r['created_at']})
    return {'users': users}


@app.delete('/api/auth/users/{user_id}')
def api_delete_user(request: Request, user_id: int):
    """Admin-only: delete a user by id. Safeguards: cannot delete yourself; cannot remove the last admin."""
    admin = _require_admin(request)
    if user_id == admin['id']:
        raise HTTPException(status_code=400, detail='Cannot delete the currently authenticated admin via this endpoint')

    conn = _get_conn()
    cur = conn.execute('SELECT id, username, is_admin FROM users WHERE id = ?', (user_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail='User not found')

    if row['is_admin']:
        # count other admins
        cur2 = conn.execute('SELECT COUNT(1) as cnt FROM users WHERE is_admin = 1')
        c = cur2.fetchone()
        try:
            admin_count = c['cnt']
        except Exception:
            admin_count = c[0]
        if admin_count <= 1:
            conn.close()
            raise HTTPException(status_code=400, detail='Cannot delete the last admin user')

    # delete any sessions for this user
    conn.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    # Also clear from in-memory token cache any tokens belonging to deleted user
    to_remove = [t for t, v in list(_TOKEN_CACHE.items()) if v.get('user_id') == user_id]
    for t in to_remove:
        _TOKEN_CACHE.pop(t, None)

    return {'status': 'ok', 'deleted_user_id': user_id}


@app.post("/api/cost")
async def api_cost_analysis(request: Request, plan_file: UploadFile = File(...), region: str = Form(None), usage_hours: float = Form(730.0), output_format: str = Form("json")):
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

    # require authenticated user
    _require_auth(request)

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
async def api_cve_action(request: Request, action: str = Form(...), data_file: UploadFile = File(None), query: str = Form(None), include_history: bool = Form(False)):
    """
    API endpoint to run CVE related actions.
    action: one of 'update', 'bulk-download', 'search', 'stats'
    For 'search', provide 'query' (keywords or technology).
    For 'update' or 'bulk-download', no extra fields required; server will run the appropriate command.
    """
    # require authenticated user for CVE actions
    _require_auth(request)

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
        # For potentially dangerous actions like update and bulk-download, require admin
        if action in ('update', 'bulk-download'):
            _require_admin(request)

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

