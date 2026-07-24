import os
from functools import wraps
from datetime import datetime, timezone

import requests
import bleach
from flask import Flask, render_template, redirect, url_for, session, request, jsonify, abort
from dotenv import load_dotenv

from supabase_client import supabase

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

# Cookie hardening - only relax "Secure" while developing over plain http locally
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_DEV_INSECURE_COOKIE") != "1"

DISCORD_API_BASE = "https://discord.com/api/v10"
MANAGE_GUILD_PERMISSION = 0x20    # bit flag for "Manage Server"
ADMINISTRATOR_PERMISSION = 0x8    # implicitly grants every permission, including Manage Server


# ---------- Discord OAuth helpers ----------

def exchange_code(code: str) -> dict:
    """Trade the one-time `code` Discord sent to /dashboard?code=... for an access token."""
    data = {
        "client_id": os.environ["DISCORD_CLIENT_ID"],
        "client_secret": os.environ["DISCORD_CLIENT_SECRET"],
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": os.environ["DISCORD_REDIRECT_URI"],
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(f"{DISCORD_API_BASE}/oauth2/token", data=data, headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_discord_user(access_token: str) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(f"{DISCORD_API_BASE}/users/@me", headers=headers)
    resp.raise_for_status()
    return resp.json()


def avatar_url(user_id: str, avatar_hash: str | None) -> str:
    if avatar_hash:
        ext = "gif" if avatar_hash.startswith("a_") else "png"
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{ext}?size=128"
    default_index = (int(user_id) >> 22) % 6
    return f"https://cdn.discordapp.com/embed/avatars/{default_index}.png"


def get_user_guilds(access_token: str) -> list[dict]:
    """Fetch every server the logged-in user belongs to, with their permission bits."""
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=headers)
    resp.raise_for_status()
    return resp.json()


def has_manage_guild(permissions: str) -> bool:
    """Discord sends permissions as a stringified integer bitfield.
    ADMINISTRATOR implicitly grants every permission (including Manage Server),
    so either bit qualifies."""
    try:
        perms = int(permissions)
    except (TypeError, ValueError):
        return False
    return bool(perms & (MANAGE_GUILD_PERMISSION | ADMINISTRATOR_PERMISSION))


def guild_icon_url(guild_id: str, icon_hash: str | None) -> str | None:
    if not icon_hash:
        return None
    ext = "gif" if icon_hash.startswith("a_") else "png"
    return f"https://cdn.discordapp.com/icons/{guild_id}/{icon_hash}.{ext}?size=128"


def guild_initials(name: str) -> str:
    """Fallback badge text for servers with no icon set, e.g. 'Acme Community' -> 'AC'."""
    words = name.split()
    return "".join(w[0] for w in words[:2]).upper()


def get_guild_details(guild_id: str) -> dict | None:
    """Fetch a guild's live details (member count, etc.) using the bot token.
    Only works if the bot is actually in that server - returns None otherwise."""
    headers = {"Authorization": f"Bot {os.environ['DISCORD_BOT_TOKEN']}"}
    resp = requests.get(f"{DISCORD_API_BASE}/guilds/{guild_id}?with_counts=true", headers=headers)
    if resp.status_code != 200:
        return None
    return resp.json()


def login_required(view):
    """Blocks a route unless the user has a logged-in session. Redirects home otherwise."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "discord_id" not in session:
            return redirect(url_for("home"))
        return view(*args, **kwargs)
    return wrapped


# ---------- Main pages ----------

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')


@app.route('/docs')
def docs():
    return render_template('docs.html')


@app.route('/updates')
def updates():
    return render_template('updates.html')


@app.route('/status')
def status():
    return render_template('status.html')


@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy.html')


@app.route('/terms-service')
def terms_service():
    return render_template('terms.html')


# ---------- Auth-gated dashboard ----------

@app.route('/dashboard')
def dashboard():
    code = request.args.get('code')

    # First arrival back from Discord's consent screen: exchange the code, start the session.
    if code and 'discord_id' not in session:
        token_data = exchange_code(code)
        access_token = token_data['access_token']
        user = get_discord_user(access_token)

        session['discord_id'] = user['id']
        session['username'] = user['username']
        session['display_name'] = user.get('global_name') or user['username']
        session['avatar_url'] = avatar_url(user['id'], user.get('avatar'))
        # NOTE: dev-only. The access token lives in Flask's signed (not encrypted) cookie
        # session for now. Fine while building, but before shipping, move this server-side
        # (Flask-Session with Redis, or a sessions table keyed by a random session id).
        session['discord_access_token'] = access_token

        # Redirect to a clean /dashboard so ?code=... doesn't linger (refreshing would
        # otherwise resend an already-used, now-invalid code)
        return redirect(url_for('dashboard'))

    # No session and no code - block access, send them to the homepage
    if 'discord_id' not in session:
        return redirect(url_for('home'))

    # Fetch the user's servers, keeping only the ones where they have Manage Server
    access_token = session.get('discord_access_token')
    manageable_guilds = []
    if access_token:
        try:
            all_guilds = get_user_guilds(access_token)
        except requests.HTTPError:
            # Access token expired or was revoked - clear the stale session and make them log in again
            session.clear()
            return redirect(url_for('home'))

        for g in all_guilds:
            if has_manage_guild(g.get('permissions', '0')):
                manageable_guilds.append({
                    'id': g['id'],
                    'name': g['name'],
                    'icon_url': guild_icon_url(g['id'], g.get('icon')),
                    'initials': guild_initials(g['name']),
                })
        manageable_guilds.sort(key=lambda g: g['name'].lower())

    # Work out which server is the "active" one in the workspace switcher
    guild_ids = {g['id'] for g in manageable_guilds}
    requested_guild_id = request.args.get('guild')
    if requested_guild_id and requested_guild_id in guild_ids:
        # User clicked a different server in the dropdown - switch to it
        session['active_guild_id'] = requested_guild_id
    elif session.get('active_guild_id') not in guild_ids:
        # No valid selection yet (first visit, or their access to the old pick was revoked)
        session['active_guild_id'] = manageable_guilds[0]['id'] if manageable_guilds else None

    selected_guild = next(
        (g for g in manageable_guilds if g['id'] == session.get('active_guild_id')),
        None,
    )
    guild_details = get_guild_details(selected_guild['id']) if selected_guild else None

    return render_template(
        'dashboard.html',
        username=session.get('username'),
        display_name=session.get('display_name', session.get('username')),
        avatar_url=session.get('avatar_url'),
        guilds=manageable_guilds,
        selected_guild=selected_guild,
        guild_details=guild_details,
    )


@app.route('/editor')
@login_required
def editor():
    return render_template('editor.html', guild_id=session.get('active_guild_id', ''))


def log_activity(guild_id: str, icon: str, message: str) -> None:
    supabase.table('activity_log').insert({
        'guild_id': guild_id,
        'icon': icon,
        'message': message,
    }).execute()


ALLOWED_BLOCK_TAGS = ['b', 'i', 'u', 'strong', 'em', 'ul', 'li', 'br']


def sanitize_blocks(blocks):
    """Strip anything beyond simple text formatting from block content before it's
    stored - published pages are public, so unsanitized HTML here would be a
    stored XSS hole (anyone hitting the API could plant a <script> tag)."""
    clean = []
    for block in blocks:
        block = dict(block)
        if isinstance(block.get('text'), str):
            block['text'] = bleach.clean(block['text'], tags=ALLOWED_BLOCK_TAGS, attributes={}, strip=True)
        clean.append(block)
    return clean


@app.route('/api/pages', methods=['GET'])
@login_required
def api_list_pages():
    guild_id = session.get('active_guild_id')
    if not guild_id:
        return jsonify([])
    resp = supabase.table('pages').select('*').eq('guild_id', guild_id).order('updated_at', desc=True).execute()
    return jsonify(resp.data)


@app.route('/api/pages', methods=['POST'])
@login_required
def api_create_page():
    guild_id = session.get('active_guild_id')
    if not guild_id:
        return jsonify({'error': 'No server selected'}), 400

    body = request.get_json(silent=True) or {}
    row = {
        'guild_id': guild_id,
        'title': body.get('title', 'Untitled Page'),
        'icon': body.get('icon', 'fa-file'),
        'status': 'draft',
        'blocks': sanitize_blocks(body.get('blocks', [])),
    }
    resp = supabase.table('pages').insert(row).execute()
    new_page = resp.data[0]
    log_activity(guild_id, 'fa-file-circle-plus', f"<strong>{new_page['title']}</strong> was created")
    return jsonify(new_page)


@app.route('/api/pages/<int:page_id>', methods=['GET'])
@login_required
def api_get_page(page_id):
    guild_id = session.get('active_guild_id')
    resp = supabase.table('pages').select('*').eq('id', page_id).eq('guild_id', guild_id).limit(1).execute()
    if not resp.data:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(resp.data[0])


@app.route('/api/pages/<int:page_id>', methods=['PUT'])
@login_required
def api_update_page(page_id):
    guild_id = session.get('active_guild_id')
    body = request.get_json(silent=True) or {}

    # Confirm this page actually belongs to the currently active server before touching it -
    # stops someone editing a page in a server they don't (or no longer) have access to.
    existing = supabase.table('pages').select('id, title, status').eq('id', page_id).eq('guild_id', guild_id).limit(1).execute()
    if not existing.data:
        return jsonify({'error': 'Not found'}), 404

    updates = {}
    for field in ('title', 'icon', 'status', 'blocks'):
        if field in body:
            updates[field] = sanitize_blocks(body[field]) if field == 'blocks' else body[field]
    updates['updated_at'] = datetime.now(timezone.utc).isoformat()

    resp = supabase.table('pages').update(updates).eq('id', page_id).execute()
    updated = resp.data[0]

    if 'status' in updates and updates['status'] != existing.data[0]['status']:
        status_labels = {'published': 'published', 'draft': 'moved to drafts', 'archived': 'archived', 'trash': 'moved to trash'}
        log_activity(guild_id, 'fa-pen', f"<strong>{updated['title']}</strong> was {status_labels.get(updates['status'], 'updated')}")

    return jsonify(updated)


@app.route('/api/pages/<int:page_id>', methods=['DELETE'])
@login_required
def api_delete_page(page_id):
    guild_id = session.get('active_guild_id')
    existing = supabase.table('pages').select('id, title').eq('id', page_id).eq('guild_id', guild_id).limit(1).execute()
    if not existing.data:
        return jsonify({'error': 'Not found'}), 404

    title = existing.data[0]['title']
    supabase.table('pages').delete().eq('id', page_id).execute()
    log_activity(guild_id, 'fa-trash', f"<strong>{title}</strong> was permanently deleted")
    return jsonify({'ok': True})


@app.route('/api/activity', methods=['GET'])
@login_required
def api_list_activity():
    guild_id = session.get('active_guild_id')
    if not guild_id:
        return jsonify([])
    resp = supabase.table('activity_log').select('*').eq('guild_id', guild_id).order('created_at', desc=True).limit(20).execute()
    return jsonify(resp.data)


@app.route('/p/<int:page_id>')
def view_published_page(page_id):
    resp = supabase.table('pages').select('*').eq('id', page_id).eq('status', 'published').limit(1).execute()
    if not resp.data:
        abort(404)
    page = resp.data[0]
    if not isinstance(page.get('blocks'), list):
        page['blocks'] = []
    page['blocks'] = sanitize_blocks(page['blocks'])
    return render_template('public_page.html', page=page)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# ---------- Placeholder routes for footer links ----------

@app.route('/support')
def support():
    return render_template('support.html')


@app.route('/discord-server')
def discord_server():
    return redirect('https://discord.gg/AfhfheSrcA')


@app.route('/twitter')
def twitter():
    return redirect('https://twitter.com/')


@app.route('/github')
def github():
    return redirect('https://github.com/')


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=9017,
        debug=False
    )