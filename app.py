import json
import os
import secrets
from datetime import datetime
from functools import wraps

import bcrypt
from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for, jsonify)

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# On Render, use /data (persistent disk). Locally, use the backend dir.
DATA_DIR = os.environ.get('RENDER_DATA_DIR', '/data') if os.path.isdir('/data') else BASE_DIR
CONTENT_FILE = os.path.join(DATA_DIR, 'content.json')
CONFIG_FILE = os.path.join(DATA_DIR, 'config.json')
MESSAGES_FILE = os.path.join(DATA_DIR, 'messages.json')
HISTORY_FILE = os.path.join(DATA_DIR, 'content_history.json')

# On first deploy: copy seed files from repo into the persistent data dir
SEED_CONTENT = os.path.join(BASE_DIR, 'content.json')
SEED_CONFIG = os.path.join(BASE_DIR, 'config.json')
if not os.path.exists(CONTENT_FILE) and os.path.exists(SEED_CONTENT):
    import shutil
    shutil.copy2(SEED_CONTENT, CONTENT_FILE)
if not os.path.exists(CONFIG_FILE) and os.path.exists(SEED_CONFIG):
    import shutil
    shutil.copy2(SEED_CONFIG, CONFIG_FILE)


# ── Load helpers ───────────────────────────────────────────────────────────
def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ── App setup ──────────────────────────────────────────────────────────────
config = load_json(CONFIG_FILE)

app = Flask(__name__, instance_path=BASE_DIR, template_folder=os.path.join(BASE_DIR, 'templates'))
app.secret_key = config.get('secret_key', secrets.token_hex(32))


# ── CSRF helpers ───────────────────────────────────────────────────────────
def generate_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(24)
    return session['csrf_token']


def validate_csrf(token):
    return token and token == session.get('csrf_token')


app.jinja_env.globals['csrf_token'] = generate_csrf


# ── Auth decorator ─────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ── Context processor ──────────────────────────────────────────────────────
@app.context_processor
def inject_globals():
    cfg = load_json(CONFIG_FILE)
    return dict(site_config=cfg, csrf_token=generate_csrf())


# ══════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            flash('Ongeldig formuliertoken.', 'error')
            return redirect(url_for('login'))
        password = request.form.get('password', '')
        cfg = load_json(CONFIG_FILE)
        stored_hash = cfg.get('admin_password_hash', '').encode()
        if bcrypt.checkpw(password.encode(), stored_hash):
            session['logged_in'] = True
            session.permanent = False
            flash('Welkom terug!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Ongeldig wachtwoord.', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Je bent uitgelogd.', 'success')
    return redirect(url_for('login'))


# ══════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════

@app.route('/')
@login_required
def dashboard():
    cfg = load_json(CONFIG_FILE)
    content = load_json(CONTENT_FILE)

    # File modification times
    content_mtime = os.path.getmtime(CONTENT_FILE)
    config_mtime = os.path.getmtime(CONFIG_FILE)

    content_modified = datetime.fromtimestamp(content_mtime).strftime('%d-%m-%Y %H:%M')
    config_modified = datetime.fromtimestamp(config_mtime).strftime('%d-%m-%Y %H:%M')

    sections = ['hero', 'platform', 'services', 'agents', 'hitl', 'consultancy', 'trust', 'cta', 'footer', 'nav']

    return render_template('dashboard.html',
                           cfg=cfg,
                           content=content,
                           sections=sections,
                           content_modified=content_modified,
                           config_modified=config_modified)


# ══════════════════════════════════════════════════════════════════════════
# CONTENT ROUTES
# ══════════════════════════════════════════════════════════════════════════

@app.route('/content')
@login_required
def content_index():
    content = load_json(CONTENT_FILE)
    return render_template('content/index.html', content=content)


@app.route('/content/hero', methods=['GET', 'POST'])
@login_required
def content_hero():
    content = load_json(CONTENT_FILE)
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            flash('Ongeldig formuliertoken.', 'error')
            return redirect(url_for('content_hero'))
        f = request.form
        # pills
        pills = [v.strip() for v in f.getlist('pills[]') if v.strip()]
        # stats
        stat_nums = f.getlist('stat_num[]')
        stat_labels = f.getlist('stat_label[]')
        stats = [{'num': n.strip(), 'label': l.strip()}
                 for n, l in zip(stat_nums, stat_labels) if n.strip()]
        content['hero'] = {
            'title': f.get('title', ''),
            'title_accent': f.get('title_accent', ''),
            'subtitle': f.get('subtitle', ''),
            'cta_primary': f.get('cta_primary', ''),
            'cta_secondary': f.get('cta_secondary', ''),
            'pills': pills,
            'stats': stats,
        }
        save_content_with_history(content)
        flash('Hero sectie opgeslagen!', 'success')
        return redirect(url_for('content_hero'))
    return render_template('content/hero.html', content=content)


@app.route('/content/platform', methods=['GET', 'POST'])
@login_required
def content_platform():
    content = load_json(CONTENT_FILE)
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            flash('Ongeldig formuliertoken.', 'error')
            return redirect(url_for('content_platform'))
        f = request.form
        icons = f.getlist('card_icon[]')
        icon_bgs = f.getlist('card_icon_bg[]')
        titles = f.getlist('card_title[]')
        descs = f.getlist('card_desc[]')
        cards = []
        for i, t in enumerate(titles):
            if t.strip():
                cards.append({
                    'icon_emoji': icons[i] if i < len(icons) else '',
                    'icon_bg': icon_bgs[i] if i < len(icon_bgs) else '',
                    'title': t.strip(),
                    'desc': descs[i].strip() if i < len(descs) else '',
                })
        content['platform'] = {
            'section_label': f.get('section_label', ''),
            'title': f.get('title', ''),
            'subtitle': f.get('subtitle', ''),
            'cards': cards,
        }
        save_content_with_history(content)
        flash('Platform sectie opgeslagen!', 'success')
        return redirect(url_for('content_platform'))
    return render_template('content/platform.html', content=content)


@app.route('/content/services', methods=['GET', 'POST'])
@login_required
def content_services():
    content = load_json(CONTENT_FILE)
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            flash('Ongeldig formuliertoken.', 'error')
            return redirect(url_for('content_services'))
        f = request.form
        nums = f.getlist('card_num[]')
        badge_labels = f.getlist('badge_label[]')
        badge_colors = f.getlist('badge_color[]')
        titles = f.getlist('card_title[]')
        descs = f.getlist('card_desc[]')
        # items are passed as card_items_0[], card_items_1[], etc.
        cards = []
        for i, t in enumerate(titles):
            if t.strip():
                items = f.getlist(f'card_items_{i}[]')
                items = [it.strip() for it in items if it.strip()]
                cards.append({
                    'num': nums[i] if i < len(nums) else '',
                    'badge_label': badge_labels[i] if i < len(badge_labels) else '',
                    'badge_color': badge_colors[i] if i < len(badge_colors) else '',
                    'title': t.strip(),
                    'desc': descs[i].strip() if i < len(descs) else '',
                    'items': items,
                })
        content['services'] = {
            'section_label': f.get('section_label', ''),
            'title': f.get('title', ''),
            'subtitle': f.get('subtitle', ''),
            'cards': cards,
        }
        save_content_with_history(content)
        flash('Diensten sectie opgeslagen!', 'success')
        return redirect(url_for('content_services'))
    return render_template('content/services.html', content=content)


@app.route('/content/agents', methods=['GET', 'POST'])
@login_required
def content_agents():
    content = load_json(CONTENT_FILE)
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            flash('Ongeldig formuliertoken.', 'error')
            return redirect(url_for('content_agents'))
        f = request.form
        names = f.getlist('card_name[]')
        roles = f.getlist('card_role[]')
        examples = f.getlist('card_example[]')
        cards = []
        for i, name in enumerate(names):
            if name.strip():
                features = f.getlist(f'card_features_{i}[]')
                features = [ft.strip() for ft in features if ft.strip()]
                cards.append({
                    'name': name.strip(),
                    'role': roles[i].strip() if i < len(roles) else '',
                    'features': features,
                    'example': examples[i].strip() if i < len(examples) else '',
                })
        content['agents'] = {
            'section_label': f.get('section_label', ''),
            'title': f.get('title', ''),
            'subtitle': f.get('subtitle', ''),
            'cards': cards,
        }
        save_content_with_history(content)
        flash('Agents sectie opgeslagen!', 'success')
        return redirect(url_for('content_agents'))
    return render_template('content/agents.html', content=content)


@app.route('/content/consultancy', methods=['GET', 'POST'])
@login_required
def content_consultancy():
    content = load_json(CONTENT_FILE)
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            flash('Ongeldig formuliertoken.', 'error')
            return redirect(url_for('content_consultancy'))
        f = request.form
        titles = f.getlist('card_title[]')
        cards = []
        for i, t in enumerate(titles):
            if t.strip():
                item_labels = f.getlist(f'item_label_{i}[]')
                item_colors = f.getlist(f'item_color_{i}[]')
                items = [{'color': c, 'label': l}
                         for c, l in zip(item_colors, item_labels) if l.strip()]
                cards.append({'title': t.strip(), 'items': items})
        content['consultancy'] = {
            'section_label': f.get('section_label', ''),
            'title': f.get('title', ''),
            'subtitle': f.get('subtitle', ''),
            'cards': cards,
        }
        save_content_with_history(content)
        flash('Consultancy sectie opgeslagen!', 'success')
        return redirect(url_for('content_consultancy'))
    return render_template('content/consultancy.html', content=content)


@app.route('/content/nav', methods=['GET', 'POST'])
@login_required
def content_nav():
    content = load_json(CONTENT_FILE)
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            flash('Ongeldig formuliertoken.', 'error')
            return redirect(url_for('content_nav'))
        f = request.form
        labels = f.getlist('link_label[]')
        hrefs = f.getlist('link_href[]')
        links = [{'label': l.strip(), 'href': h.strip()}
                 for l, h in zip(labels, hrefs) if l.strip()]
        content['nav'] = {
            'links': links,
            'cta_label': f.get('cta_label', ''),
        }
        save_content_with_history(content)
        flash('Navigatie opgeslagen!', 'success')
        return redirect(url_for('content_nav'))
    return render_template('content/nav.html', content=content)


# ══════════════════════════════════════════════════════════════════════════
# SETTINGS ROUTES
# ══════════════════════════════════════════════════════════════════════════

@app.route('/security', methods=['GET', 'POST'])
@login_required
def security():
    cfg = load_json(CONFIG_FILE)
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            flash('Ongeldig formuliertoken.', 'error')
            return redirect(url_for('security'))
        action = request.form.get('action')

        if action == 'change_password':
            current_pw = request.form.get('current_password', '')
            new_pw = request.form.get('new_password', '')
            confirm_pw = request.form.get('confirm_password', '')
            stored_hash = cfg.get('admin_password_hash', '').encode()
            if not bcrypt.checkpw(current_pw.encode(), stored_hash):
                flash('Huidig wachtwoord is onjuist.', 'error')
            elif new_pw != confirm_pw:
                flash('Nieuwe wachtwoorden komen niet overeen.', 'error')
            elif len(new_pw) < 6:
                flash('Wachtwoord moet minimaal 6 tekens zijn.', 'error')
            else:
                new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                cfg['admin_password_hash'] = new_hash
                save_json(CONFIG_FILE, cfg)
                flash('Wachtwoord succesvol gewijzigd!', 'success')

        elif action == 'save_settings':
            cfg['force_https'] = 'force_https' in request.form
            cfg['rate_limit_enabled'] = 'rate_limit_enabled' in request.form
            cfg['maintenance_mode'] = 'maintenance_mode' in request.form
            try:
                cfg['rate_limit_per_minute'] = int(request.form.get('rate_limit_per_minute', 60))
            except ValueError:
                cfg['rate_limit_per_minute'] = 60
            cfg['google_analytics_id'] = request.form.get('google_analytics_id', '').strip()
            cfg['contact_email'] = request.form.get('contact_email', '').strip()
            save_json(CONFIG_FILE, cfg)
            flash('Instellingen opgeslagen!', 'success')

        return redirect(url_for('security'))
    return render_template('security.html', cfg=cfg)


@app.route('/domain', methods=['GET', 'POST'])
@login_required
def domain():
    cfg = load_json(CONFIG_FILE)
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            flash('Ongeldig formuliertoken.', 'error')
            return redirect(url_for('domain'))
        cfg['domain'] = request.form.get('domain', '').strip().rstrip('/')
        save_json(CONFIG_FILE, cfg)
        flash('Domein opgeslagen!', 'success')
        return redirect(url_for('domain'))
    return render_template('domain.html', cfg=cfg)


@app.route('/theme', methods=['GET', 'POST'])
@login_required
def theme():
    cfg = load_json(CONFIG_FILE)
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            flash('Ongeldig formuliertoken.', 'error')
            return redirect(url_for('theme'))
        theme_data = {
            'primary_color': request.form.get('primary_color', '#2563EB'),
            'accent_color': request.form.get('accent_color', '#0d6e52'),
            'bg_color': request.form.get('bg_color', '#ffffff'),
            'surface_color': request.form.get('surface_color', '#f9f9fa'),
            'text_color': request.form.get('text_color', '#171717'),
            'heading_font': request.form.get('heading_font', 'Outfit'),
            'body_font': request.form.get('body_font', 'DM Sans'),
            'base_font_size': request.form.get('base_font_size', '16'),
            'section_spacing': request.form.get('section_spacing', '100'),
            'card_radius': request.form.get('card_radius', '20'),
        }
        cfg['theme'] = theme_data
        save_json(CONFIG_FILE, cfg)
        flash('Thema opgeslagen!', 'success')
        return redirect(url_for('theme'))
    return render_template('theme.html', cfg=cfg)


@app.route('/content/blocks', methods=['GET', 'POST'])
@login_required
def content_blocks():
    content = load_json(CONTENT_FILE)
    if 'custom_blocks' not in content:
        content['custom_blocks'] = []
    if request.method == 'POST':
        if not validate_csrf(request.form.get('csrf_token')):
            flash('Ongeldig formuliertoken.', 'error')
            return redirect(url_for('content_blocks'))
        action = request.form.get('action')
        if action == 'add':
            block_type = request.form.get('block_type', 'text')
            block = {
                'id': f'block_{int(datetime.now().timestamp())}',
                'type': block_type,
                'label': request.form.get('label', 'Nieuw blok'),
                'title': request.form.get('title', 'Nieuwe sectie'),
                'text': request.form.get('text', ''),
                'items': [],
            }
            if block_type == 'stats':
                nums = request.form.getlist('stat_num[]')
                labels = request.form.getlist('stat_label[]')
                block['items'] = [{'num': n.strip(), 'label': l.strip()} for n, l in zip(nums, labels) if n.strip()]
            elif block_type == 'columns':
                col_a_items = [x.strip() for x in request.form.getlist('col_a[]') if x.strip()]
                col_b_items = [x.strip() for x in request.form.getlist('col_b[]') if x.strip()]
                block['col_a_title'] = request.form.get('col_a_title', 'Kolom A')
                block['col_b_title'] = request.form.get('col_b_title', 'Kolom B')
                block['items'] = [{'col_a': a, 'col_b': b} for a, b in zip(col_a_items, col_b_items)]
            content['custom_blocks'].append(block)
        elif action == 'delete':
            block_id = request.form.get('block_id')
            content['custom_blocks'] = [b for b in content['custom_blocks'] if b['id'] != block_id]
        elif action == 'update':
            block_id = request.form.get('block_id')
            for block in content['custom_blocks']:
                if block['id'] == block_id:
                    block['label'] = request.form.get('label', block['label'])
                    block['title'] = request.form.get('title', block['title'])
                    block['text'] = request.form.get('text', block.get('text', ''))
                    break
        save_json(CONTENT_FILE, content)
        flash('Blokken bijgewerkt!', 'success')
        return redirect(url_for('content_blocks'))
    return render_template('content/blocks.html', content=content)


# HISTORY_FILE and MESSAGES_FILE already defined above

def save_content_with_history(content):
    """Save content and keep a history snapshot for undo."""
    history = []
    if os.path.exists(HISTORY_FILE):
        history = load_json(HISTORY_FILE)
    # Keep max 20 snapshots
    current = load_json(CONTENT_FILE)
    history.insert(0, {'timestamp': datetime.now().isoformat(), 'data': current})
    if len(history) > 20:
        history = history[:20]
    save_json(HISTORY_FILE, history)
    save_json(CONTENT_FILE, content)


# ══════════════════════════════════════════════════════════════════════════
# CONTACT FORM (public)
# ══════════════════════════════════════════════════════════════════════════

def load_messages():
    if not os.path.exists(MESSAGES_FILE):
        return []
    return load_json(MESSAGES_FILE)

def save_messages(msgs):
    save_json(MESSAGES_FILE, msgs)

@app.route('/api/contact', methods=['POST'])
def api_contact():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Geen data ontvangen'}), 400
        naam = data.get('naam', '').strip()
        email = data.get('email', '').strip()
        onderwerp = data.get('onderwerp', '').strip()
        bericht = data.get('bericht', '').strip()
        if not naam or not email or not bericht:
            return jsonify({'error': 'Naam, email en bericht zijn verplicht'}), 400
        msgs = load_messages()
        msgs.insert(0, {
            'naam': naam,
            'email': email,
            'onderwerp': onderwerp,
            'bericht': bericht,
            'timestamp': datetime.now().isoformat(),
            'read': False
        })
        save_messages(msgs)
        return jsonify({'ok': True, 'message': 'Bericht verzonden!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════
# MESSAGES
# ══════════════════════════════════════════════════════════════════════════

@app.route('/messages')
@login_required
def messages():
    msgs = load_messages()
    return render_template('messages.html', messages=msgs)

@app.route('/api/messages/<int:idx>/read', methods=['POST'])
@login_required
def mark_message_read(idx):
    msgs = load_messages()
    if 0 <= idx < len(msgs):
        msgs[idx]['read'] = True
        save_messages(msgs)
    return jsonify({'ok': True})

@app.route('/api/messages/<int:idx>/delete', methods=['POST'])
@login_required
def delete_message(idx):
    msgs = load_messages()
    if 0 <= idx < len(msgs):
        msgs.pop(idx)
        save_messages(msgs)
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════════════════
# AJAX API ROUTES
# ══════════════════════════════════════════════════════════════════════════

@app.route('/api/content', methods=['POST'])
@login_required
def api_content():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data'}), 400
        content = load_json(CONTENT_FILE)
        content.update(data)
        save_content_with_history(content)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/undo', methods=['POST'])
@login_required
def api_undo():
    if not os.path.exists(HISTORY_FILE):
        return jsonify({'error': 'Geen geschiedenis beschikbaar'}), 400
    history = load_json(HISTORY_FILE)
    if not history:
        return jsonify({'error': 'Geen geschiedenis beschikbaar'}), 400
    prev = history.pop(0)
    save_json(HISTORY_FILE, history)
    save_json(CONTENT_FILE, prev['data'])
    return jsonify({'ok': True, 'message': 'Vorige versie hersteld'})


@app.route('/api/config', methods=['POST'])
@login_required
def api_config():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data'}), 400
        cfg = load_json(CONFIG_FILE)
        # Never allow overwriting the password hash via API
        data.pop('admin_password_hash', None)
        cfg.update(data)
        save_json(CONFIG_FILE, cfg)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════
# WEBSITE / PREVIEW
# ══════════════════════════════════════════════════════════════════════════

@app.route('/website')
def website():
    """Public-facing website — no login required."""
    content = load_json(CONTENT_FILE)
    cfg = load_json(CONFIG_FILE)
    return render_template('website.html', content=content, cfg=cfg)


@app.route('/logo.png')
def logo_png():
    """Serve the Aiventity logo from the static folder."""
    import os
    from flask import send_from_directory
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    return send_from_directory(static_dir, 'logo.png', mimetype='image/png')


@app.route('/preview')
@login_required
def preview():
    return redirect(url_for('website'))


@app.route('/public')
def public_site():
    """Alias for /website — share this URL with customers."""
    return redirect(url_for('website'))


# ══════════════════════════════════════════════════════════════════════════
# NETLIFY PUBLISH
# ══════════════════════════════════════════════════════════════════════════

@app.route('/publish-netlify')
@login_required
def publish_netlify():
    import urllib.request, hashlib, re as _re, os as _os
    import json as _json
    cfg = load_json(CONFIG_FILE)
    token = cfg.get('netlify_token', '')
    site_id = cfg.get('netlify_site_id', '')

    if not token or not site_id:
        flash('Netlify token of site ID ontbreekt in config.', 'error')
        return redirect(url_for('dashboard'))

    try:
        # Render website HTML and strip the Flask admin bar
        html = render_template('website.html', content=load_json(CONTENT_FILE), cfg=cfg)
        html = _re.sub(r'<!-- Flask Admin Bar -->.*?</div>\n', '', html, flags=_re.DOTALL)
        html_bytes = html.encode('utf-8')

        headers_bytes = b"/*\n  Content-Type: text/html; charset=utf-8\n  Cache-Control: public, max-age=0, must-revalidate\n"

        # Load logo
        logo_path = _os.path.join(_os.path.dirname(__file__), 'static', 'logo.png')
        with open(logo_path, 'rb') as f:
            logo_bytes = f.read()

        html_sha1  = hashlib.sha1(html_bytes).hexdigest()
        hdrs_sha1  = hashlib.sha1(headers_bytes).hexdigest()
        logo_sha1  = hashlib.sha1(logo_bytes).hexdigest()

        # Create deploy manifest (HTML + headers + logo)
        manifest = _json.dumps({"files": {
            "/index.html":   html_sha1,
            "/website.html": html_sha1,
            "/_headers":     hdrs_sha1,
            "/logo.png":     logo_sha1,
        }}).encode()

        req = urllib.request.Request(
            f"https://api.netlify.com/api/v1/sites/{site_id}/deploys",
            data=manifest,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as r:
            deploy = _json.loads(r.read())

        deploy_id = deploy["id"]
        required  = deploy.get("required", [])

        files_map = {
            html_sha1:  ("index.html",   html_bytes,    "text/html; charset=utf-8"),
            hdrs_sha1:  ("_headers",     headers_bytes, "text/plain"),
            logo_sha1:  ("logo.png",     logo_bytes,    "image/png"),
        }
        for sha in required:
            if sha in files_map:
                path, data, ctype = files_map[sha]
                req2 = urllib.request.Request(
                    f"https://api.netlify.com/api/v1/deploys/{deploy_id}/files/{path}",
                    data=data,
                    headers={"Authorization": f"Bearer {token}", "Content-Type": ctype},
                    method="PUT"
                )
                with urllib.request.urlopen(req2) as r2:
                    r2.read()

        flash('✅ Website gepubliceerd op aiventitytool.netlify.app!', 'success')
    except Exception as e:
        flash(f'Fout bij publiceren: {str(e)}', 'error')

    return redirect(url_for('dashboard'))


# ══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
