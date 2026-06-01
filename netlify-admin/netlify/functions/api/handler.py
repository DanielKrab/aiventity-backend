"""
Aiventity CMS — Netlify Functions Backend
100% Netlify: no Render, no external servers.
Storage: GitHub API (data branch)
Auth:    HMAC-signed Bearer tokens (stateless)
"""
import json, os, base64, hashlib, hmac, time, secrets
import urllib.request, urllib.error
from pathlib import Path
from datetime import datetime

import bcrypt
from jinja2 import Environment, FileSystemLoader

# ── Config (Netlify env vars) ──────────────────────────────────────────────
SECRET_KEY     = os.environ.get('SECRET_KEY', 'changeme-set-in-netlify-env')
ADMIN_HASH     = os.environ.get('ADMIN_HASH', '')        # bcrypt hash
GITHUB_TOKEN   = os.environ.get('GITHUB_TOKEN', '')
GITHUB_OWNER   = os.environ.get('GITHUB_OWNER', 'DanielKrab')
GITHUB_REPO    = os.environ.get('GITHUB_REPO', 'aiventity-backend')
GITHUB_BRANCH  = os.environ.get('GITHUB_BRANCH', 'data')
NETLIFY_TOKEN  = os.environ.get('NETLIFY_TOKEN', '')
PUBLIC_SITE_ID = os.environ.get('PUBLIC_SITE_ID', '5559f234-9246-4edf-a2c5-778983c63285')

TOKEN_TTL = 86400 * 7   # 7 days

# ── Jinja2 ─────────────────────────────────────────────────────────────────
TMPL_DIR = Path(__file__).parent / 'templates'
jinja = Environment(loader=FileSystemLoader(str(TMPL_DIR)), autoescape=True)

# ── CORS headers ───────────────────────────────────────────────────────────
CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
}

# ══════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════

def _sign(payload: str) -> str:
    return hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()

def make_token() -> str:
    exp = str(int(time.time()) + TOKEN_TTL)
    sig = _sign(exp)
    return f"{exp}.{sig}"

def verify_token(token: str) -> bool:
    try:
        exp, sig = token.rsplit('.', 1)
        if not hmac.compare_digest(_sign(exp), sig):
            return False
        return int(exp) > int(time.time())
    except Exception:
        return False

def get_bearer(event) -> str:
    hdrs = event.get('headers') or {}
    auth = hdrs.get('authorization') or hdrs.get('Authorization') or ''
    return auth[7:] if auth.startswith('Bearer ') else ''

def is_auth(event) -> bool:
    return verify_token(get_bearer(event))

# ══════════════════════════════════════════════════════════════════════════
# GITHUB STORAGE
# ══════════════════════════════════════════════════════════════════════════

GH_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "Content-Type": "application/json",
    "User-Agent": "AiventityCMS/1.0",
}

def gh_get(path: str):
    """Read a file from the data branch. Returns (parsed_json, sha) or ({}, None)."""
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}?ref={GITHUB_BRANCH}"
    req = urllib.request.Request(url, headers=GH_HEADERS)
    try:
        with urllib.request.urlopen(req) as r:
            info = json.loads(r.read())
            content = json.loads(base64.b64decode(info['content']).decode('utf-8'))
            return content, info['sha']
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}, None
        raise
    except Exception:
        return {}, None

def gh_put(path: str, data: dict, sha=None, msg="CMS update"):
    """Create or update a JSON file on the data branch."""
    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}"
    body = {
        "message": msg,
        "content": base64.b64encode(
            json.dumps(data, ensure_ascii=False, indent=2).encode()
        ).decode(),
        "branch": GITHUB_BRANCH,
    }
    if sha:
        body["sha"] = sha
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers=GH_HEADERS, method="PUT"
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

def load_content():
    return gh_get('content.json')

def load_config():
    return gh_get('config.json')

def save_content(data, sha=None):
    return gh_put('content.json', data, sha, "CMS: save content")

def save_config(data, sha=None):
    return gh_put('config.json', data, sha, "CMS: save config")

# ══════════════════════════════════════════════════════════════════════════
# RESPONSE HELPERS
# ══════════════════════════════════════════════════════════════════════════

def resp(status, body, extra_headers=None):
    h = {**CORS, "Content-Type": "application/json"}
    if extra_headers:
        h.update(extra_headers)
    return {"statusCode": status, "headers": h, "body": json.dumps(body, ensure_ascii=False)}

def unauth():
    return resp(401, {"error": "Niet ingelogd"})

def bad(msg="Ongeldig verzoek"):
    return resp(400, {"error": msg})

# ══════════════════════════════════════════════════════════════════════════
# ROUTE HANDLERS
# ══════════════════════════════════════════════════════════════════════════

def handle_login(event):
    try:
        body = json.loads(event.get('body') or '{}')
    except Exception:
        return bad()
    pw = body.get('password', '')
    if not ADMIN_HASH:
        return resp(500, {"error": "ADMIN_HASH not set in environment"})
    try:
        if bcrypt.checkpw(pw.encode(), ADMIN_HASH.encode()):
            return resp(200, {"ok": True, "token": make_token()})
    except Exception as e:
        return resp(500, {"error": str(e)})
    return resp(401, {"error": "Ongeldig wachtwoord"})


def handle_get_content(event):
    content, _ = load_content()
    return resp(200, content)


def handle_post_content(event):
    try:
        updates = json.loads(event.get('body') or '{}')
    except Exception:
        return bad()
    content, sha = load_content()
    for section, fields in updates.items():
        content[section] = {**content.get(section, {}), **fields}
    save_content(content, sha)
    return resp(200, {"ok": True})


def handle_get_config(event):
    cfg, _ = load_config()
    # Don't expose secrets to the browser
    safe = {k: v for k, v in cfg.items()
            if k not in ('admin_password_hash', 'secret_key')}
    return resp(200, safe)


def handle_post_config(event):
    try:
        updates = json.loads(event.get('body') or '{}')
    except Exception:
        return bad()
    cfg, sha = load_config()
    allowed = [
        'site_name', 'site_tagline', 'seo_meta_title', 'seo_meta_description',
        'og_image_url', 'canonical_url', 'twitter_url', 'linkedin_url',
        'instagram_url', 'github_url', 'google_analytics_id', 'contact_email',
        'favicon_url', 'netlify_token', 'netlify_site_id',
    ]
    for k in allowed:
        if k in updates and updates[k] != '':
            cfg[k] = updates[k]
    save_config(cfg, sha)
    return resp(200, {"ok": True})


def handle_publish(event):
    content, _ = load_content()
    cfg, sha_cfg = load_config()
    token   = cfg.get('netlify_token') or NETLIFY_TOKEN
    site_id = cfg.get('netlify_site_id') or PUBLIC_SITE_ID
    if not token or not site_id:
        return resp(500, {"error": "Netlify token of site ID ontbreekt"})
    try:
        # Render the website
        html = jinja.get_template('website.html').render(content=content, cfg=cfg)
        html_bytes = html.encode('utf-8')
        html_sha1 = hashlib.sha1(html_bytes).hexdigest()

        headers_bytes = (
            "/*\n  Content-Type: text/html; charset=utf-8\n"
            "  Cache-Control: public, max-age=0, must-revalidate\n"
        ).encode()
        hdrs_sha1 = hashlib.sha1(headers_bytes).hexdigest()

        manifest = json.dumps({"files": {
            "/index.html":   html_sha1,
            "/website.html": html_sha1,
            "/_headers":     hdrs_sha1,
        }}).encode()

        req = urllib.request.Request(
            f"https://api.netlify.com/api/v1/sites/{site_id}/deploys",
            data=manifest,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            deploy = json.loads(r.read())

        deploy_id = deploy["id"]
        required  = deploy.get("required", [])
        files_map = {
            html_sha1: ("index.html",  html_bytes,    "text/html; charset=utf-8"),
            hdrs_sha1: ("_headers",    headers_bytes, "text/plain"),
        }
        for sha in required:
            if sha in files_map:
                fname, data, ctype = files_map[sha]
                r2 = urllib.request.Request(
                    f"https://api.netlify.com/api/v1/deploys/{deploy_id}/files/{fname}",
                    data=data,
                    headers={"Authorization": f"Bearer {token}", "Content-Type": ctype},
                    method="PUT"
                )
                with urllib.request.urlopen(r2, timeout=30) as rr:
                    rr.read()

        # Save publish timestamp
        cfg['last_published'] = datetime.now().strftime('%Y-%m-%d %H:%M')
        save_config(cfg, sha_cfg)
        return resp(200, {"ok": True, "message": "✅ Website gepubliceerd op Netlify!"})
    except Exception as e:
        return resp(500, {"error": f"Publiceren mislukt: {e}"})


def handle_publish_status(event):
    cfg, _ = load_config()
    return resp(200, {"last_published": cfg.get('last_published')})


def handle_history(event):
    history, _ = gh_get('content_history.json')
    if not history:
        history = []
    if not isinstance(history, list):
        history = []
    return resp(200, history[-20:])


def handle_restore(event, idx: int):
    history, sha_h = gh_get('content_history.json')
    if not isinstance(history, list) or idx >= len(history):
        return bad("Snapshot niet gevonden")
    # Save backup first
    content, sha_c = load_content()
    backup = {"label": "Auto-backup voor herstel", "timestamp": datetime.now().isoformat(),
               "data": content}
    history.append(backup)
    # Restore
    content = history[idx]['data']
    save_content(content, sha_c)
    history_data, sha_hist = gh_get('content_history.json')
    if not isinstance(history_data, list):
        history_data = []
    history_data.append(backup)
    gh_put('content_history.json', history_data[-20:], sha_hist, "CMS: restore snapshot")
    return resp(200, {"ok": True})


# ══════════════════════════════════════════════════════════════════════════
# MAIN HANDLER
# ══════════════════════════════════════════════════════════════════════════

def handler(event, context):
    method = (event.get('httpMethod') or 'GET').upper()
    path   = event.get('path') or '/'

    # CORS preflight
    if method == 'OPTIONS':
        return {"statusCode": 204, "headers": CORS, "body": ""}

    # ── Public ──
    if path == '/api/login' and method == 'POST':
        return handle_login(event)

    # ── Protected ──
    if not is_auth(event):
        return unauth()

    if path == '/api/content':
        if method == 'GET':   return handle_get_content(event)
        if method == 'POST':  return handle_post_content(event)

    if path == '/api/config':
        if method == 'GET':   return handle_get_config(event)
        if method == 'POST':  return handle_post_config(event)

    if path == '/api/publish' and method == 'POST':
        return handle_publish(event)

    if path == '/api/publish-status' and method == 'GET':
        return handle_publish_status(event)

    if path == '/api/history' and method == 'GET':
        return handle_history(event)

    if path.startswith('/api/restore/') and method == 'POST':
        try:
            idx = int(path.split('/')[-1])
            return handle_restore(event, idx)
        except ValueError:
            return bad()

    return resp(404, {"error": "Route niet gevonden"})
