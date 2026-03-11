"""
KanGo - Lightweight Kanban Task Board
Cloud Run + GCS JSON backend
"""

import os
import json
import uuid
import hashlib
import functools
import logging
from collections import defaultdict
from datetime import datetime, timezone
from time import time as _now

import urllib.request
import urllib.error
from flask import (Flask, request, jsonify, make_response,
                   redirect, session)

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "kango-dev-key-change-me")

GCS_BUCKET = os.environ.get("GCS_BUCKET", "kango-tasks-esj-bk")
PASSWORD_HASH = os.environ.get(
    "PASSWORD_HASH",
    hashlib.sha256("kango2026".encode()).hexdigest(),
)
STRATOSX_LOGIN_URL = os.environ.get(
    "STRATOSX_LOGIN_URL",
    "https://app.stratosx.com/api/auth/login",
)
CRON_SECRET = os.environ.get("CRON_SECRET", "")
BACKUP_DEST_BUCKET = "stratosx-backups-esj"
BACKUP_SOURCE_BUCKETS = [
    "stratosx-data-esj",
    "kango-tasks-esj-bk",
    "stratosx-mind-cloud",
    "stratosx-criteria-builder",
]

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("kango")


# ──────────────────────────────────────────────
# Security headers (X-Content-Type-Options, X-Frame-Options)
# ──────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ──────────────────────────────────────────────
# Rate limiter for /login (in-memory, 5 per minute per IP)
# ──────────────────────────────────────────────
_login_attempts = defaultdict(list)   # {ip: [timestamp, ...]}
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 60  # seconds


def _check_rate_limit(ip):
    """Return True if request is allowed, False if rate-limited."""
    now = _now()
    attempts = _login_attempts[ip]
    # prune old entries
    _login_attempts[ip] = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
    if len(_login_attempts[ip]) >= RATE_LIMIT_MAX:
        return False
    _login_attempts[ip].append(now)
    return True

BUCKETS_ORDER = [
    "auto-recommended",
    "manually-recommended",
    "for-production",
    "for-tests-confirm",
    "delivered",
    "done",
]

BUCKET_LABELS = {
    "auto-recommended": "\U0001f916 Auto-Recommended",
    "manually-recommended": "\U0001f4dd Manually Recommended",
    "for-production": "\U0001f680 For Production",
    "for-tests-confirm": "\U0001f9ea For Tests \u2014 Confirm",
    "delivered": "\U0001f4e6 Delivered",
    "done": "\u2705 Done",
}

BUCKET_COLORS = {
    "auto-recommended": "#6366f1",
    "manually-recommended": "#3b82f6",
    "for-production": "#f59e0b",
    "for-tests-confirm": "#8b5cf6",
    "delivered": "#10b981",
    "done": "#6b7280",
}

DEFAULT_APPS = [
    "StratosX", "GeoCatch", "CriteriaBuilder", "MindCloud",
    "OralB Dashboard", "PDPCatch", "StratosX Brand", "KanGo",
]

# ──────────────────────────────────────────────
# GCS helpers  (lazy init — no import at module level)
# ──────────────────────────────────────────────
_storage_client = None


def _gcs():
    global _storage_client
    if _storage_client is None:
        log.info("Initializing GCS client...")
        from google.cloud import storage as gcs_lib
        _storage_client = gcs_lib.Client()
        log.info("GCS client ready.")
    return _storage_client


def load_tasks():
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blob = bucket.blob("tasks.json")
        if blob.exists():
            return json.loads(blob.download_as_text())
    except Exception as exc:
        log.error("GCS read error: %s", exc)
    return {"tasks": [], "apps": list(DEFAULT_APPS)}


def save_tasks(data):
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blob = bucket.blob("tasks.json")
        blob.upload_from_string(
            json.dumps(data, ensure_ascii=False, indent=2),
            content_type="application/json",
        )
        return True
    except Exception as exc:
        log.error("GCS write error: %s", exc)
        return False


# ──────────────────────────────────────────────
# Auth
# ──────────────────────────────────────────────
def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("authed"):
            if request.is_json:
                return jsonify({"error": "unauthorized"}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    error_div = ""
    if request.method == "POST":
        ip = request.headers.get("X-Forwarded-For",
                                 request.remote_addr or "unknown")
        if not _check_rate_limit(ip):
            error_div = '<div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-xl"><div class="flex items-center space-x-2"><svg class="w-4 h-4 text-red-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg><span class="text-sm text-red-600">Too many attempts. Try again in 60 seconds.</span></div></div>'
            html = LOGIN_PAGE.replace("{{ERROR}}", error_div)
            resp = make_response(html, 429)
            resp.headers["Content-Type"] = "text/html; charset=utf-8"
            return resp
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")

        # --- Strategy 1: authenticate via StratosX (admins only) ---
        authed = False
        user_name = ""
        if email and pw:
            try:
                payload = json.dumps({"email": email, "password": pw}).encode()
                req = urllib.request.Request(
                    STRATOSX_LOGIN_URL,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode())
                        if data.get("status") == "ok" and data.get("role") == "admin":
                            authed = True
                            user_name = data.get("name", email)
            except Exception:
                log.warning("StratosX auth unreachable, falling back")

        # --- Strategy 2: fallback legacy password (no email needed) ---
        if not authed and pw:
            if hashlib.sha256(pw.encode()).hexdigest() == PASSWORD_HASH:
                authed = True
                user_name = "admin"

        if authed:
            session["authed"] = True
            session["user_name"] = user_name
            return redirect("/")

        error_div = '<div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-xl"><div class="flex items-center space-x-2"><svg class="w-4 h-4 text-red-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg><span class="text-sm text-red-600">Invalid credentials or insufficient permissions (admin only)</span></div></div>'

    html = LOGIN_PAGE.replace("{{ERROR}}", error_div)
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ──────────────────────────────────────────────
# Health
# ──────────────────────────────────────────────
@app.route("/healthz")
@app.route("/health")
def healthz():
    return "ok", 200


# ──────────────────────────────────────────────
# API
# ──────────────────────────────────────────────
@app.route("/api/tasks", methods=["GET"])
@login_required
def api_get_tasks():
    return jsonify(load_tasks())


@app.route("/api/tasks", methods=["POST"])
@login_required
def api_create_task():
    data = load_tasks()
    body = request.get_json(force=True)
    task = {
        "id": str(uuid.uuid4())[:12],
        "title": body.get("title", "Untitled"),
        "description": body.get("description", ""),
        "prompt": body.get("prompt", ""),
        "priority": body.get("priority", "medium"),
        "tags": body.get("tags", []),
        "app": body.get("app", ""),
        "app_directory": body.get("app_directory", ""),
        "bucket": body.get("bucket", "manually-recommended"),
        "estimated_time": body.get("estimated_time", ""),
        "comment": body.get("comment", ""),
        "source": body.get("source", "manual"),
        "done": body.get("done", False),
        "archived": body.get("archived", False),
        "in_progress": body.get("in_progress", False),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "order": body.get("order", 999),
    }
    data["tasks"].append(task)
    save_tasks(data)
    return jsonify(task), 201


@app.route("/api/tasks/<task_id>", methods=["PUT"])
@login_required
def api_update_task(task_id):
    data = load_tasks()
    body = request.get_json(force=True)
    for t in data["tasks"]:
        if t["id"] == task_id:
            for key in ("title", "description", "prompt",
                        "priority", "tags", "app",
                        "app_directory", "bucket",
                        "estimated_time", "comment",
                        "order", "source",
                        "done", "archived", "in_progress"):
                if key in body:
                    t[key] = body[key]
            t["updated_at"] = datetime.now(timezone.utc).isoformat()
            save_tasks(data)
            return jsonify(t)
    return jsonify({"error": "not found"}), 404


@app.route("/api/tasks/<task_id>", methods=["DELETE"])
@login_required
def api_delete_task(task_id):
    data = load_tasks()
    data["tasks"] = [t for t in data["tasks"] if t["id"] != task_id]
    save_tasks(data)
    return jsonify({"ok": True})


@app.route("/api/reorder", methods=["POST"])
@login_required
def api_reorder():
    data = load_tasks()
    body = request.get_json(force=True)
    task_map = {t["id"]: t for t in data["tasks"]}
    for u in body.get("updates", []):
        tid = u.get("id")
        if tid in task_map:
            task_map[tid]["bucket"] = u["bucket"]
            task_map[tid]["order"] = u["order"]
            task_map[tid]["updated_at"] = datetime.now(timezone.utc).isoformat()
    save_tasks(data)
    return jsonify({"ok": True})


@app.route("/api/apps", methods=["POST"])
@login_required
def api_add_app():
    data = load_tasks()
    body = request.get_json(force=True)
    name = body.get("name", "").strip()
    if name and name not in data.get("apps", []):
        data.setdefault("apps", []).append(name)
        save_tasks(data)
    return jsonify({"apps": data.get("apps", [])})


# ──────────────────────────────────────────────
# Export / Import
# ──────────────────────────────────────────────
@app.route("/api/export", methods=["GET"])
@login_required
def api_export():
    """Export all tasks + apps as a downloadable JSON file."""
    data = load_tasks()
    export = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "version": "1.0",
        "tasks": data.get("tasks", []),
        "apps": data.get("apps", []),
    }
    payload = json.dumps(export, ensure_ascii=False, indent=2)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    resp = make_response(payload)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = (
        'attachment; filename="kango_export_%s.json"' % ts
    )
    return resp


@app.route("/api/import", methods=["POST"])
@login_required
def api_import():
    """Import tasks from a JSON file (merge or replace)."""
    mode = request.args.get("mode", "merge")  # merge | replace
    if "file" in request.files:
        raw = request.files["file"].read()
    else:
        raw = request.get_data()
    try:
        incoming = json.loads(raw)
    except Exception:
        return jsonify({"error": "invalid JSON"}), 400

    incoming_tasks = incoming.get("tasks", [])
    incoming_apps = incoming.get("apps", [])

    if mode == "replace":
        data = {"tasks": incoming_tasks,
                "apps": incoming_apps or list(DEFAULT_APPS)}
    else:
        data = load_tasks()
        existing_ids = {t["id"] for t in data["tasks"]}
        for t in incoming_tasks:
            if t["id"] not in existing_ids:
                data["tasks"].append(t)
            else:
                for i, et in enumerate(data["tasks"]):
                    if et["id"] == t["id"]:
                        data["tasks"][i] = t
                        break
        for a in incoming_apps:
            if a not in data.get("apps", []):
                data.setdefault("apps", []).append(a)

    save_tasks(data)
    return jsonify({
        "ok": True,
        "mode": mode,
        "tasks": len(data["tasks"]),
        "apps": len(data.get("apps", [])),
    })


# ──────────────────────────────────────────────
# File Management (GCS "files/" prefix)
# ──────────────────────────────────────────────
FILES_PREFIX = "files/"


@app.route("/api/files", methods=["GET"])
@login_required
def api_list_files():
    """List all uploaded files."""
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blobs = bucket.list_blobs(prefix=FILES_PREFIX)
        files = []
        for b in blobs:
            name = b.name[len(FILES_PREFIX):]
            if not name:
                continue
            files.append({
                "name": name,
                "size": b.size,
                "updated": b.updated.isoformat() if b.updated else "",
                "url": "/api/files/" + name,
            })
        return jsonify({"files": files})
    except Exception as exc:
        log.error("File list error: %s", exc)
        return jsonify({"files": []})


PREVIEWABLE_TYPES = {
    "text/html", "text/plain", "text/css", "text/csv",
    "application/json", "application/javascript", "application/pdf",
    "image/png", "image/jpeg", "image/gif", "image/svg+xml", "image/webp",
}
PREVIEWABLE_EXTS = {
    ".html", ".htm", ".txt", ".css", ".csv", ".json", ".js",
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
}


@app.route("/api/files/<path:filename>", methods=["GET"])
@login_required
def api_download_file(filename):
    """Download or preview a file from GCS.
    ?preview=1 → inline Content-Disposition (show in browser).
    Otherwise → attachment (force download).
    """
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blob = bucket.blob(FILES_PREFIX + filename)
        if not blob.exists():
            return jsonify({"error": "not found"}), 404
        content = blob.download_as_bytes()
        resp = make_response(content)
        ct = blob.content_type or "application/octet-stream"
        ext = os.path.splitext(filename)[-1].lower()
        # Decide inline vs attachment
        want_preview = request.args.get("preview") == "1"
        can_preview = ct in PREVIEWABLE_TYPES or ext in PREVIEWABLE_EXTS
        if want_preview and can_preview:
            resp.headers["Content-Disposition"] = (
                'inline; filename="%s"' % filename.split("/")[-1]
            )
        else:
            resp.headers["Content-Disposition"] = (
                'attachment; filename="%s"' % filename.split("/")[-1]
            )
        resp.headers["Content-Type"] = ct
        return resp
    except Exception as exc:
        log.error("File download error: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/files", methods=["POST"])
@login_required
def api_upload_file():
    """Upload a file to GCS. Accepts multipart form-data."""
    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400
    safe_name = f.filename.replace("..", "").replace("/", "_")
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blob = bucket.blob(FILES_PREFIX + safe_name)
        blob.upload_from_file(f, content_type=f.content_type)
        return jsonify({
            "name": safe_name,
            "url": "/api/files/" + safe_name,
            "size": blob.size,
        }), 201
    except Exception as exc:
        log.error("File upload error: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/files/<path:filename>", methods=["DELETE"])
@login_required
def api_delete_file(filename):
    """Delete a file from GCS."""
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blob = bucket.blob(FILES_PREFIX + filename)
        if blob.exists():
            blob.delete()
        return jsonify({"ok": True})
    except Exception as exc:
        log.error("File delete error: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ──────────────────────────────────────────────
# Public file sharing (hash-based, no login)
# ──────────────────────────────────────────────
PUBLIC_PREFIX = "public/"


def _file_hash(filename):
    """Deterministic short hash for a filename."""
    return hashlib.sha256(
        ("kango-public-" + filename).encode()
    ).hexdigest()[:12]


@app.route("/api/files/<path:filename>/public", methods=["POST"])
@login_required
def api_make_file_public(filename):
    """Create a public shareable link for a file."""
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blob = bucket.blob(FILES_PREFIX + filename)
        if not blob.exists():
            return jsonify({"error": "not found"}), 404
        fhash = _file_hash(filename)
        # Store mapping: public/<hash>.json → filename
        meta_blob = bucket.blob(PUBLIC_PREFIX + fhash + ".json")
        meta_blob.upload_from_string(
            json.dumps({"filename": filename,
                        "created": datetime.now(
                            timezone.utc).isoformat()}),
            content_type="application/json",
        )
        public_url = "/public/" + fhash
        return jsonify({"hash": fhash,
                        "public_url": public_url}), 201
    except Exception as exc:
        log.error("Make public error: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/files/<path:filename>/public", methods=["DELETE"])
@login_required
def api_revoke_file_public(filename):
    """Revoke public access for a file."""
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        fhash = _file_hash(filename)
        meta_blob = bucket.blob(PUBLIC_PREFIX + fhash + ".json")
        if meta_blob.exists():
            meta_blob.delete()
        return jsonify({"ok": True})
    except Exception as exc:
        log.error("Revoke public error: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/files/<path:filename>/public", methods=["GET"])
@login_required
def api_get_file_public_status(filename):
    """Check if a file has a public link."""
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        fhash = _file_hash(filename)
        meta_blob = bucket.blob(PUBLIC_PREFIX + fhash + ".json")
        if meta_blob.exists():
            return jsonify({"public": True,
                            "hash": fhash,
                            "public_url": "/public/" + fhash})
        return jsonify({"public": False})
    except Exception as exc:
        return jsonify({"public": False})


@app.route("/public/<file_hash>")
def public_file(file_hash):
    """Serve a publicly shared file — NO login required."""
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        meta_blob = bucket.blob(
            PUBLIC_PREFIX + file_hash + ".json")
        if not meta_blob.exists():
            return "Not found or link expired", 404
        meta = json.loads(meta_blob.download_as_text())
        filename = meta["filename"]
        blob = bucket.blob(FILES_PREFIX + filename)
        if not blob.exists():
            return "File not found", 404
        content = blob.download_as_bytes()
        resp = make_response(content)
        ct = blob.content_type or "application/octet-stream"
        ext = os.path.splitext(filename)[-1].lower()
        can_preview = (ct in PREVIEWABLE_TYPES
                       or ext in PREVIEWABLE_EXTS)
        if can_preview:
            resp.headers["Content-Disposition"] = (
                'inline; filename="%s"' % filename.split("/")[-1]
            )
        else:
            resp.headers["Content-Disposition"] = (
                'attachment; filename="%s"'
                % filename.split("/")[-1]
            )
        resp.headers["Content-Type"] = ct
        return resp
    except Exception as exc:
        log.error("Public file error: %s", exc)
        return "Error", 500


# ──────────────────────────────────────────────
# File Metadata (title, description, tags) — stored in GCS
# ──────────────────────────────────────────────
FILES_META_BLOB = "files_meta.json"


def _load_files_meta():
    """Load {filename: {title, description, tags}} from GCS."""
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blob = bucket.blob(FILES_META_BLOB)
        if blob.exists():
            return json.loads(blob.download_as_text())
    except Exception as exc:
        log.error("Load files meta error: %s", exc)
    return {}


def _save_files_meta(meta):
    """Persist file metadata to GCS."""
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blob = bucket.blob(FILES_META_BLOB)
        blob.upload_from_string(
            json.dumps(meta, ensure_ascii=False, indent=2),
            content_type="application/json",
        )
    except Exception as exc:
        log.error("Save files meta error: %s", exc)


@app.route("/api/files/<path:filename>/meta", methods=["GET"])
@login_required
def api_get_file_meta(filename):
    """Get metadata for a single file."""
    meta = _load_files_meta()
    fm = meta.get(filename, {})
    return jsonify({
        "name": filename,
        "title": fm.get("title", ""),
        "description": fm.get("description", ""),
        "tags": fm.get("tags", []),
    })


@app.route("/api/files/<path:filename>/meta", methods=["PUT"])
@login_required
def api_update_file_meta(filename):
    """Update title, description, tags for a file."""
    body = request.get_json(force=True) or {}
    meta = _load_files_meta()
    entry = meta.get(filename, {})
    if "title" in body:
        entry["title"] = body["title"]
    if "description" in body:
        entry["description"] = body["description"]
    if "tags" in body:
        entry["tags"] = [t.strip() for t in body["tags"]
                         if isinstance(t, str) and t.strip()]
    meta[filename] = entry
    _save_files_meta(meta)
    return jsonify({"ok": True, **entry})


@app.route("/api/files-meta", methods=["GET"])
@login_required
def api_all_files_meta():
    """Get metadata for all files (for the files page)."""
    meta = _load_files_meta()
    return jsonify(meta)


# ──────────────────────────────────────────────
# Files Page — full-page SERP-style file browser
# ──────────────────────────────────────────────
@app.route("/files")
@login_required
def files_page():
    resp = make_response(FILES_PAGE)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ──────────────────────────────────────────────
# Board page  — plain string replacement, NO Jinja
# ──────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    log.info("Serving board page...")
    bucket_options = "".join(
        '<option value="{b}">{l}</option>'.format(b=b, l=BUCKET_LABELS[b])
        for b in BUCKETS_ORDER
    )
    html = BOARD_PAGE
    html = html.replace("__BUCKETS_JSON__", json.dumps(BUCKETS_ORDER))
    html = html.replace("__LABELS_JSON__", json.dumps(BUCKET_LABELS, ensure_ascii=False))
    html = html.replace("__COLORS_JSON__", json.dumps(BUCKET_COLORS))
    html = html.replace("__BUCKET_OPTIONS__", bucket_options)

    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    log.info("Board page served, %d bytes", len(html))
    return resp


# ══════════════════════════════════════════════
# HTML Templates (plain strings — no Jinja2)
# ══════════════════════════════════════════════

LOGIN_PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KanGo &mdash; Sign In</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config={darkMode:'class',theme:{extend:{fontFamily:{outfit:['Outfit','sans-serif']},colors:{primary:{50:'#eff6ff',100:'#dbeafe',500:'#3b82f6',600:'#2563eb',700:'#1d4ed8'},brand:{dark:'#1e293b'}}}}}
</script>
<style>
body{font-family:'Outfit',sans-serif}
@keyframes fadeInUp{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
.fade-in{animation:fadeInUp .5s ease-out}
@keyframes float{0%,100%{transform:translateY(0) rotate(0deg)}50%{transform:translateY(-10px) rotate(1deg)}}
.float-anim{animation:float 6s ease-in-out infinite}
</style></head>
<body class="bg-gray-50 min-h-screen flex font-outfit">

<!-- LEFT: Branding Panel -->
<div class="hidden lg:flex lg:w-1/2 relative overflow-hidden bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900">
  <div class="absolute inset-0">
    <div class="absolute top-20 left-10 w-72 h-72 bg-white/5 rounded-full blur-3xl"></div>
    <div class="absolute bottom-10 right-10 w-96 h-96 bg-blue-400/10 rounded-full blur-3xl"></div>
    <div class="absolute top-1/2 left-1/3 w-40 h-40 border border-white/10 rounded-2xl rotate-12 float-anim"></div>
    <div class="absolute bottom-1/4 right-1/4 w-24 h-24 border border-white/10 rounded-xl -rotate-6 float-anim" style="animation-delay:2s"></div>
    <div class="absolute inset-0" style="background-image:radial-gradient(rgba(255,255,255,0.05) 1px,transparent 1px);background-size:32px 32px"></div>
  </div>
  <div class="relative z-10 flex flex-col justify-center px-16 max-w-lg mx-auto">
    <div class="mb-10">
      <div class="flex items-center gap-3">
        <div class="w-11 h-11 bg-blue-500/20 rounded-xl flex items-center justify-center text-2xl">&#x1F4CB;</div>
        <span class="text-white text-2xl font-bold tracking-tight">KanGo</span>
      </div>
    </div>
    <h1 class="text-4xl font-bold text-white leading-tight mb-4">
      Lightweight Kanban<br>for the
      <span class="text-blue-300">StratosX</span><br>ecosystem
    </h1>
    <p class="text-blue-200/70 text-base leading-relaxed mb-10">
      Drag-and-drop task management built for Cloud Run microservices.
      Track recommendations, ship to production, iterate fast.
    </p>
    <div class="flex gap-3">
      <div class="px-4 py-2 bg-white/10 rounded-full text-white/80 text-sm font-medium backdrop-blur-sm">&#x1F680; Cloud Run</div>
      <div class="px-4 py-2 bg-white/10 rounded-full text-white/80 text-sm font-medium backdrop-blur-sm">&#x2601; GCS Backend</div>
      <div class="px-4 py-2 bg-white/10 rounded-full text-white/80 text-sm font-medium backdrop-blur-sm">&#x1F512; Secret Mgr</div>
    </div>
  </div>
</div>

<!-- RIGHT: Login Form -->
<div class="flex-1 flex items-center justify-center px-6 py-12">
  <div class="w-full max-w-md fade-in">
    <div class="lg:hidden flex justify-center mb-8">
      <div class="flex items-center gap-2">
        <span class="text-3xl">&#x1F4CB;</span>
        <span class="text-2xl font-bold text-gray-900">KanGo</span>
      </div>
    </div>
    <div class="bg-white rounded-2xl shadow-xl shadow-gray-200/50 border border-gray-100 p-8 md:p-10">
      <div class="mb-8">
        <h2 class="text-2xl font-bold text-gray-900">Welcome back</h2>
        <p class="text-sm text-gray-500 mt-1">Sign in to KanGo</p>
      </div>
      {{ERROR}}
      <form method="POST" class="space-y-5">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1.5">Email</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
              <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75"/></svg>
            </span>
            <input type="email" name="email" autofocus
              class="w-full pl-11 pr-4 py-3 text-sm border border-gray-300 rounded-xl bg-white text-gray-900 placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition"
              placeholder="you@stratosx.com">
          </div>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1.5">Password</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
              <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"/></svg>
            </span>
            <input type="password" name="password" required
              class="w-full pl-11 pr-4 py-3 text-sm border border-gray-300 rounded-xl bg-white text-gray-900 placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition"
              placeholder="Enter password...">
          </div>
        </div>
        <button type="submit"
          class="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-xl shadow-lg shadow-blue-500/25 transition-all duration-200 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
          Sign In
        </button>
      </form>
      <p class="text-center text-xs text-gray-400 mt-6">StratosX Ecosystem &bull; KanGo v1.0 &bull; Admin access via StratosX credentials</p>
    </div>
  </div>
</div>
</body></html>"""


# ══════════════════════════════════════════════
# FILES PAGE — Google SERP–style file browser
# ══════════════════════════════════════════════
FILES_PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KanGo &mdash; Files</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{fontFamily:{outfit:['Outfit','sans-serif']}}}}</script>
<style>
body{font-family:'Outfit',sans-serif}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.fade-in{animation:fadeIn .3s ease-out both}
.serp-card:hover{box-shadow:0 4px 24px rgba(0,0,0,0.06)}
.tag-pill{transition:all .15s}
.tag-pill:hover{filter:brightness(0.92)}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:10px}
</style></head>
<body class="bg-slate-50 font-outfit min-h-screen">

<!-- TOP BAR -->
<header class="bg-white border-b border-slate-200 sticky top-0 z-50">
  <div class="max-w-5xl mx-auto flex items-center justify-between px-6 h-16">
    <div class="flex items-center gap-3">
      <a href="/" class="flex items-center gap-3 hover:opacity-80 transition">
        <div class="w-9 h-9 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-xl flex items-center justify-center text-white text-lg shadow-lg shadow-blue-500/20">&#x1F4CB;</div>
        <div>
          <h1 class="text-lg font-bold text-slate-900 leading-none">KanGo</h1>
          <p class="text-[10px] text-slate-400 font-medium tracking-wide uppercase">Files</p>
        </div>
      </a>
    </div>
    <div class="flex items-center gap-2">
      <a href="/" class="inline-flex items-center gap-1.5 px-3 py-2 text-slate-500 hover:text-slate-700 hover:bg-slate-50 text-sm font-medium rounded-xl border border-slate-200 transition-all">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25"/></svg>
        Board
      </a>
      <label class="inline-flex items-center gap-2 px-3 py-2 text-slate-500 hover:text-blue-600 hover:bg-blue-50 text-sm font-medium rounded-xl border border-dashed border-slate-300 hover:border-blue-400 cursor-pointer transition-all">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"/></svg>
        Upload
        <input type="file" class="hidden" id="fileUploadInput" onchange="uploadFile()">
      </label>
      <a href="/logout" class="inline-flex items-center gap-1.5 px-3 py-2 text-slate-400 hover:text-red-500 hover:bg-red-50 text-sm font-medium rounded-xl border border-slate-200 transition-all">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9"/></svg>
      </a>
    </div>
  </div>
</header>

<!-- SEARCH BAR (Google-style) -->
<div class="max-w-5xl mx-auto px-6 pt-8 pb-4">
  <div class="relative">
    <svg class="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"/></svg>
    <input id="searchInput" type="text" placeholder="Search files by name, title, description, or tag..." class="w-full pl-12 pr-4 py-3.5 text-sm bg-white border border-slate-200 rounded-2xl shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition font-medium" oninput="renderFiles()">
  </div>
  <!-- Tag filter bar -->
  <div id="tagBar" class="flex flex-wrap gap-2 mt-3"></div>
  <div class="flex items-center justify-between mt-3">
    <div id="resultCount" class="text-xs text-slate-400 font-medium"></div>
    <div class="flex items-center gap-2">
      <button onclick="setSortBy('date')" id="sortDate" class="text-xs px-2.5 py-1 rounded-lg bg-blue-50 text-blue-600 font-medium transition hover:bg-blue-100">Newest</button>
      <button onclick="setSortBy('name')" id="sortName" class="text-xs px-2.5 py-1 rounded-lg bg-slate-100 text-slate-500 font-medium transition hover:bg-slate-200">A–Z</button>
      <button onclick="setSortBy('size')" id="sortSize" class="text-xs px-2.5 py-1 rounded-lg bg-slate-100 text-slate-500 font-medium transition hover:bg-slate-200">Size</button>
    </div>
  </div>
</div>

<!-- SERP RESULTS -->
<main class="max-w-5xl mx-auto px-6 pb-16">
  <div id="filesList" class="space-y-4"></div>
</main>

<!-- EDIT META MODAL -->
<div class="fixed inset-0 bg-black/40 backdrop-blur-sm z-[200] hidden items-center justify-center" id="metaModal">
<div class="bg-white rounded-2xl shadow-2xl w-[540px] max-w-[94vw] max-h-[90vh] overflow-y-auto">
  <div class="px-8 pt-6 pb-4 border-b border-slate-100">
    <div class="flex items-center justify-between">
      <h2 class="text-lg font-bold text-slate-900">Edit File Info</h2>
      <button onclick="closeMetaModal()" class="w-8 h-8 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-400 hover:text-slate-600 transition">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    </div>
    <div id="metaFileName" class="text-xs text-slate-400 font-mono mt-1"></div>
  </div>
  <div class="px-8 py-5 space-y-4">
    <input type="hidden" id="metaFileKey">
    <div>
      <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Title</label>
      <input id="metaTitle" placeholder="Give this file a descriptive title..." class="w-full px-4 py-3 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition font-medium">
    </div>
    <div>
      <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Description</label>
      <textarea id="metaDesc" rows="3" placeholder="Brief description of this file's content..." class="w-full px-4 py-3 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition resize-y leading-relaxed"></textarea>
    </div>
    <div>
      <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Tags (comma-separated)</label>
      <input id="metaTags" placeholder="report, analysis, html" class="w-full px-4 py-3 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">
    </div>
  </div>
  <div class="px-8 py-4 border-t border-slate-100 flex gap-3 justify-end">
    <button class="px-5 py-2.5 text-sm font-medium text-slate-500 hover:bg-slate-50 rounded-xl border border-slate-200 transition" onclick="closeMetaModal()">Cancel</button>
    <button class="px-6 py-2.5 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl shadow-lg shadow-blue-500/20 transition" onclick="saveMeta()">Save</button>
  </div>
</div></div>

<script>
var FILES=[];
var META={};
var SORT_BY='date';
var ACTIVE_TAG=null;
var PREVIEW_EXTS=['.html','.htm','.txt','.css','.csv','.json','.js','.pdf','.png','.jpg','.jpeg','.gif','.svg','.webp'];

function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
function canPreview(name){var ext=name.substring(name.lastIndexOf('.')).toLowerCase();return PREVIEW_EXTS.indexOf(ext)>=0}
function fmtSize(b){return b<1024?(b+' B'):b<1048576?((b/1024).toFixed(1)+' KB'):((b/1048576).toFixed(1)+' MB')}
function fmtDate(iso){if(!iso)return '';var d=new Date(iso);return d.toLocaleDateString('en-GB',{day:'numeric',month:'short',year:'numeric'})}
function fileExt(name){var i=name.lastIndexOf('.');return i>=0?name.substring(i).toLowerCase():''}

// Icon + color per extension
function extInfo(name){
  var ext=fileExt(name);
  var map={
    '.html':{icon:'&#x1F310;',color:'bg-emerald-50 text-emerald-600',label:'HTML'},
    '.htm':{icon:'&#x1F310;',color:'bg-emerald-50 text-emerald-600',label:'HTML'},
    '.pdf':{icon:'&#x1F4C4;',color:'bg-red-50 text-red-500',label:'PDF'},
    '.json':{icon:'&#x1F4E6;',color:'bg-amber-50 text-amber-600',label:'JSON'},
    '.csv':{icon:'&#x1F4CA;',color:'bg-green-50 text-green-600',label:'CSV'},
    '.xlsx':{icon:'&#x1F4CA;',color:'bg-green-50 text-green-600',label:'XLSX'},
    '.png':{icon:'&#x1F5BC;',color:'bg-violet-50 text-violet-600',label:'PNG'},
    '.jpg':{icon:'&#x1F5BC;',color:'bg-violet-50 text-violet-600',label:'JPG'},
    '.jpeg':{icon:'&#x1F5BC;',color:'bg-violet-50 text-violet-600',label:'JPEG'},
    '.gif':{icon:'&#x1F5BC;',color:'bg-violet-50 text-violet-600',label:'GIF'},
    '.svg':{icon:'&#x1F5BC;',color:'bg-violet-50 text-violet-600',label:'SVG'},
    '.txt':{icon:'&#x1F4DD;',color:'bg-slate-100 text-slate-500',label:'TXT'},
    '.js':{icon:'&#x26A1;',color:'bg-yellow-50 text-yellow-600',label:'JS'},
    '.css':{icon:'&#x1F3A8;',color:'bg-blue-50 text-blue-600',label:'CSS'},
  };
  return map[ext]||{icon:'&#x1F4C1;',color:'bg-slate-100 text-slate-500',label:ext.replace('.','').toUpperCase()||'FILE'};
}

function load(){
  Promise.all([
    fetch('/api/files').then(function(r){return r.json()}),
    fetch('/api/files-meta').then(function(r){return r.json()})
  ]).then(function(results){
    FILES=results[0].files||[];
    META=results[1]||{};
    buildTagBar();
    renderFiles();
  });
}

function getAllTags(){
  var tags={};
  Object.keys(META).forEach(function(k){
    (META[k].tags||[]).forEach(function(t){tags[t]=(tags[t]||0)+1});
  });
  return Object.keys(tags).sort().map(function(t){return{name:t,count:tags[t]}});
}

function buildTagBar(){
  var tags=getAllTags();
  var bar=document.getElementById('tagBar');
  if(!tags.length){bar.innerHTML='';return}
  var h='<span class="text-[10px] text-slate-400 font-medium uppercase tracking-wider self-center mr-1">Tags:</span>';
  tags.forEach(function(t){
    var active=ACTIVE_TAG===t.name;
    h+='<button onclick="filterTag(\''+esc(t.name)+'\')" class="tag-pill text-xs font-medium px-2.5 py-1 rounded-full border '+(active?'bg-blue-600 text-white border-blue-600':'bg-white text-slate-600 border-slate-200 hover:border-blue-300 hover:text-blue-600')+' transition">'+esc(t.name)+' <span class="text-[10px] opacity-60">'+t.count+'</span></button>';
  });
  if(ACTIVE_TAG){
    h+='<button onclick="filterTag(null)" class="text-xs font-medium px-2 py-1 rounded-full text-red-500 hover:bg-red-50 transition">&times; Clear</button>';
  }
  bar.innerHTML=h;
}

function filterTag(tag){
  ACTIVE_TAG=(ACTIVE_TAG===tag)?null:tag;
  buildTagBar();
  renderFiles();
}

function setSortBy(s){
  SORT_BY=s;
  ['date','name','size'].forEach(function(k){
    var btn=document.getElementById('sort'+k.charAt(0).toUpperCase()+k.slice(1));
    if(btn){btn.className='text-xs px-2.5 py-1 rounded-lg font-medium transition '+(k===s?'bg-blue-50 text-blue-600 hover:bg-blue-100':'bg-slate-100 text-slate-500 hover:bg-slate-200')}
  });
  renderFiles();
}

function getFilteredFiles(){
  var q=(document.getElementById('searchInput').value||'').toLowerCase().trim();
  var filtered=FILES.filter(function(f){
    var m=META[f.name]||{};
    var title=(m.title||'').toLowerCase();
    var desc=(m.description||'').toLowerCase();
    var tags=(m.tags||[]).join(' ').toLowerCase();
    var name=f.name.toLowerCase();
    // Tag filter
    if(ACTIVE_TAG && (m.tags||[]).indexOf(ACTIVE_TAG)<0) return false;
    // Text search
    if(!q) return true;
    return name.indexOf(q)>=0||title.indexOf(q)>=0||desc.indexOf(q)>=0||tags.indexOf(q)>=0;
  });
  // Sort
  filtered.sort(function(a,b){
    if(SORT_BY==='date') return (b.updated||'').localeCompare(a.updated||'');
    if(SORT_BY==='name') return a.name.localeCompare(b.name);
    if(SORT_BY==='size') return (b.size||0)-(a.size||0);
    return 0;
  });
  return filtered;
}

function renderFiles(){
  var filtered=getFilteredFiles();
  var el=document.getElementById('filesList');
  document.getElementById('resultCount').textContent=filtered.length+' file'+(filtered.length!==1?'s':'')+' found';

  if(!filtered.length){
    el.innerHTML='<div class="text-center py-16"><div class="text-4xl mb-3">&#x1F4C2;</div><div class="text-slate-400 text-sm font-medium">No files match your search</div></div>';
    return;
  }

  el.innerHTML=filtered.map(function(f,i){
    var m=META[f.name]||{};
    var info=extInfo(f.name);
    var cp=canPreview(f.name);
    var title=m.title||f.name.replace(/[_-]/g,' ').replace(/\.\w+$/,'');
    var desc=m.description||'No description yet — click edit to add one.';
    var tags=(m.tags||[]);
    var url=cp?('/api/files/'+encodeURIComponent(f.name)+'?preview=1'):f.url;
    var target=cp?' target="_blank"':'';

    // SERP-style card
    var h='<div class="serp-card bg-white rounded-2xl border border-slate-100 p-5 transition-all duration-200 fade-in" style="animation-delay:'+Math.min(i*40,400)+'ms">';

    // Top row: icon + title/url + actions
    h+='<div class="flex items-start gap-4">';
    // Icon
    h+='<div class="w-12 h-12 '+info.color+' rounded-xl flex items-center justify-center text-xl flex-shrink-0 mt-0.5">'+info.icon+'</div>';
    // Content
    h+='<div class="flex-1 min-w-0">';
    // URL breadcrumb (Google-style)
    h+='<div class="flex items-center gap-1.5 mb-0.5">';
    h+='<span class="text-xs text-slate-400 truncate font-mono">'+esc(f.name)+'</span>';
    h+='<span class="text-[10px] font-bold px-1.5 py-0.5 rounded '+info.color+'">'+info.label+'</span>';
    h+='<span class="text-[10px] text-slate-400">'+fmtSize(f.size)+'</span>';
    h+='<span class="text-[10px] text-slate-300">&middot;</span>';
    h+='<span class="text-[10px] text-slate-400">'+fmtDate(f.updated)+'</span>';
    h+='</div>';
    // Title (clickable)
    h+='<a href="'+url+'"'+target+' class="text-lg font-semibold text-blue-700 hover:text-blue-500 hover:underline leading-snug block truncate">'+esc(title)+'</a>';
    // Description
    h+='<p class="text-sm text-slate-500 leading-relaxed mt-1 line-clamp-2'+(m.description?'':' italic text-slate-400')+'">'+esc(desc)+'</p>';
    // Tags
    if(tags.length){
      h+='<div class="flex flex-wrap gap-1.5 mt-2">';
      tags.forEach(function(t){
        h+='<span class="text-[11px] font-medium px-2 py-0.5 rounded-full bg-blue-50 text-blue-600 cursor-pointer hover:bg-blue-100 transition" onclick="filterTag(\''+esc(t)+'\')">'+esc(t)+'</span>';
      });
      h+='</div>';
    }
    h+='</div>'; // end content

    // Actions column
    h+='<div class="flex items-center gap-1 flex-shrink-0 mt-1">';
    if(cp) h+='<a href="'+url+'" target="_blank" class="w-9 h-9 rounded-xl bg-emerald-50 hover:bg-emerald-100 flex items-center justify-center text-emerald-600 transition" title="Preview"><svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z"/><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg></a>';
    h+='<a href="'+f.url+'" class="w-9 h-9 rounded-xl bg-slate-50 hover:bg-blue-50 flex items-center justify-center text-slate-400 hover:text-blue-600 transition" title="Download"><svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"/></svg></a>';
    h+='<button onclick="openMetaModal(\''+esc(f.name)+'\')" class="w-9 h-9 rounded-xl bg-slate-50 hover:bg-violet-50 flex items-center justify-center text-slate-400 hover:text-violet-600 transition" title="Edit info"><svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z"/></svg></button>';
    h+='<button onclick="shareFile(\''+esc(f.name)+'\')" class="w-9 h-9 rounded-xl bg-slate-50 hover:bg-indigo-50 flex items-center justify-center text-slate-400 hover:text-indigo-600 transition" title="Share public link"><svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m9.86-2.54a4.5 4.5 0 00-1.242-7.244l-4.5-4.5a4.5 4.5 0 00-6.364 6.364L4.34 8.798"/></svg></button>';
    h+='<button onclick="deleteFile(\''+esc(f.name)+'\')" class="w-9 h-9 rounded-xl bg-slate-50 hover:bg-red-50 flex items-center justify-center text-slate-400 hover:text-red-500 transition" title="Delete"><svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/></svg></button>';
    h+='</div>'; // end actions

    h+='</div>'; // end top row
    h+='</div>'; // end card
    return h;
  }).join('');
}

function uploadFile(){
  var inp=document.getElementById('fileUploadInput');
  if(!inp.files.length)return;
  var fd=new FormData();fd.append('file',inp.files[0]);
  fetch('/api/files',{method:'POST',body:fd}).then(function(){inp.value='';load()});
}

function deleteFile(name){
  if(!confirm('Delete "'+name+'"? This cannot be undone.'))return;
  fetch('/api/files/'+encodeURIComponent(name),{method:'DELETE'}).then(load);
}

function shareFile(name){
  fetch('/api/files/'+encodeURIComponent(name)+'/public')
  .then(function(r){return r.json()})
  .then(function(d){
    if(d.public){
      if(confirm('File already shared. Unpublish?')){
        fetch('/api/files/'+encodeURIComponent(name)+'/public',{method:'DELETE'}).then(function(){alert('Unpublished.')});
      } else {
        var url=location.origin+(d.public_url||'');
        prompt('Public link:',url);
        if(navigator.clipboard)navigator.clipboard.writeText(url);
      }
    } else {
      fetch('/api/files/'+encodeURIComponent(name)+'/public',{method:'POST'})
      .then(function(r){return r.json()})
      .then(function(d){
        var url=location.origin+(d.public_url||'');
        prompt('Public link (copied):',url);
        if(navigator.clipboard)navigator.clipboard.writeText(url);
      });
    }
  });
}

// Meta modal
function openMetaModal(name){
  var m=document.getElementById('metaModal');m.classList.remove('hidden');m.classList.add('flex');
  document.getElementById('metaFileKey').value=name;
  document.getElementById('metaFileName').textContent=name;
  var fm=META[name]||{};
  document.getElementById('metaTitle').value=fm.title||'';
  document.getElementById('metaDesc').value=fm.description||'';
  document.getElementById('metaTags').value=(fm.tags||[]).join(', ');
}
function closeMetaModal(){var m=document.getElementById('metaModal');m.classList.add('hidden');m.classList.remove('flex')}

function saveMeta(){
  var name=document.getElementById('metaFileKey').value;
  var body={
    title:document.getElementById('metaTitle').value,
    description:document.getElementById('metaDesc').value,
    tags:document.getElementById('metaTags').value.split(',').map(function(s){return s.trim()}).filter(Boolean)
  };
  fetch('/api/files/'+encodeURIComponent(name)+'/meta',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
  .then(function(){
    META[name]=body;
    closeMetaModal();
    buildTagBar();
    renderFiles();
  });
}

document.getElementById('metaModal').addEventListener('click',function(e){if(e.target===this)closeMetaModal()});
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeMetaModal()});

load();
</script></body></html>"""


BOARD_PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KanGo &mdash; Board</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config={darkMode:'class',theme:{extend:{fontFamily:{outfit:['Outfit','sans-serif']},colors:{primary:{50:'#eff6ff',100:'#dbeafe',500:'#3b82f6',600:'#2563eb',700:'#1d4ed8'},brand:{dark:'#1e293b'}}}}}
</script>
<style>
body{font-family:'Outfit',sans-serif}
.drag-over{background:rgba(59,130,246,0.04) !important;border-color:rgba(59,130,246,0.3) !important}
.card-drag{opacity:.4;transform:scale(.97)}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.fade-card{animation:fadeIn .25s ease-out}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:10px}
::-webkit-scrollbar-thumb:hover{background:#94a3b8}
.no-prompt-border{border-left:3px solid #ef4444 !important}
.sprint-glow{box-shadow:0 0 0 2px rgba(245,158,11,0.4),0 4px 12px rgba(245,158,11,0.15) !important;border-color:#f59e0b !important}
.in-progress-glow{box-shadow:0 0 0 2px rgba(59,130,246,0.5),0 4px 16px rgba(59,130,246,0.2) !important;border-color:#3b82f6 !important;background:linear-gradient(135deg,#eff6ff,#fff) !important}
@keyframes progressPulse{0%,100%{box-shadow:0 0 0 2px rgba(59,130,246,0.5),0 4px 16px rgba(59,130,246,0.2)}50%{box-shadow:0 0 0 3px rgba(59,130,246,0.3),0 6px 20px rgba(59,130,246,0.15)}}
.in-progress-glow{animation:progressPulse 2.5s ease-in-out infinite}
.just-done-glow{box-shadow:0 0 0 2px rgba(16,185,129,0.3),0 4px 12px rgba(16,185,129,0.1) !important;border-color:#10b981 !important}
</style></head>
<body class="bg-slate-50 font-outfit min-h-screen">

<!-- TOP BAR -->
<header class="bg-white border-b border-slate-200 sticky top-0 z-50">
  <div class="flex items-center justify-between px-6 h-16">
    <div class="flex items-center gap-3">
      <div class="w-9 h-9 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-xl flex items-center justify-center text-white text-lg shadow-lg shadow-blue-500/20">&#x1F4CB;</div>
      <div>
        <h1 class="text-lg font-bold text-slate-900 leading-none">KanGo</h1>
        <p class="text-[10px] text-slate-400 font-medium tracking-wide uppercase">Task Board</p>
      </div>
    </div>
    <div class="flex items-center gap-2">
      <!-- App filter multiselect -->
      <div class="relative" id="filterWrap">
        <button onclick="toggleFilter()" class="inline-flex items-center gap-1.5 px-3 py-2.5 text-slate-500 hover:text-slate-700 hover:bg-slate-50 text-sm font-medium rounded-xl border border-slate-200 transition-all">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 3c2.755 0 5.455.232 8.083.678.533.09.917.556.917 1.096v1.044a2.25 2.25 0 01-.659 1.591l-5.432 5.432a2.25 2.25 0 00-.659 1.591v2.927a2.25 2.25 0 01-1.244 2.013L9.75 21v-6.568a2.25 2.25 0 00-.659-1.591L3.659 7.409A2.25 2.25 0 013 5.818V4.774c0-.54.384-1.006.917-1.096A48.32 48.32 0 0112 3z"/></svg>
          <span id="filterLabel">All Apps</span>
        </button>
        <div id="filterDrop" class="hidden absolute right-0 top-full mt-1 w-56 bg-white rounded-xl shadow-xl border border-slate-200 z-50 py-2 max-h-64 overflow-y-auto"></div>
      </div>
      <button onclick="openModal()" class="inline-flex items-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-xl shadow-lg shadow-blue-500/20 transition-all">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>
        New Task
      </button>
      <button onclick="openAppModal()" class="inline-flex items-center gap-1.5 px-3 py-2.5 text-slate-500 hover:text-slate-700 hover:bg-slate-50 text-sm font-medium rounded-xl border border-slate-200 transition-all">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 010 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 010-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28z"/><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
        Apps
      </button>
      <button onclick="toggleFilesPanel()" class="inline-flex items-center gap-1.5 px-3 py-2.5 text-slate-500 hover:text-slate-700 hover:bg-slate-50 text-sm font-medium rounded-xl border border-slate-200 transition-all" title="Quick files panel">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z"/></svg>
        Files
      </button>
      <a href="/files" class="inline-flex items-center gap-1.5 px-3 py-2.5 text-slate-500 hover:text-slate-700 hover:bg-slate-50 text-sm font-medium rounded-xl border border-slate-200 transition-all" title="Full files page">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"/></svg>
        Search Files
      </a>
      <a href="/analytics" class="inline-flex items-center gap-1.5 px-3 py-2.5 text-slate-500 hover:text-violet-600 hover:bg-violet-50 text-sm font-medium rounded-xl border border-slate-200 transition-all" title="Analytics block designer">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z"/></svg>
        Analytics
      </a>
      <a href="/api/export" class="inline-flex items-center gap-1.5 px-3 py-2.5 text-slate-500 hover:text-slate-700 hover:bg-slate-50 text-sm font-medium rounded-xl border border-slate-200 transition-all" title="Export all tasks as JSON">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"/></svg>
        Export
      </a>
      <a href="/logout" class="inline-flex items-center gap-1.5 px-3 py-2.5 text-slate-400 hover:text-red-500 hover:bg-red-50 text-sm font-medium rounded-xl border border-slate-200 transition-all">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9"/></svg>
      </a>
    </div>
  </div>
  <div class="px-6 pb-3 flex items-center gap-4" id="statsBar"></div>
</header>

<!-- BOARD -->
<div class="flex gap-5 p-6 min-h-[calc(100vh-7rem)] items-start overflow-x-auto" id="board"></div>

<!-- TASK MODAL — redesigned, wider, nicer -->
<div class="fixed inset-0 bg-black/40 backdrop-blur-sm z-[200] hidden items-center justify-center" id="taskModal">
<div class="bg-white rounded-2xl shadow-2xl w-[640px] max-w-[94vw] max-h-[92vh] overflow-y-auto">
  <div class="sticky top-0 bg-white z-10 px-8 pt-6 pb-4 border-b border-slate-100 rounded-t-2xl">
    <div class="flex items-center justify-between">
      <h2 id="mTitle" class="text-xl font-bold text-slate-900">New Task</h2>
      <button onclick="closeModal()" class="w-8 h-8 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-400 hover:text-slate-600 transition">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    </div>
  </div>
  <input type="hidden" id="taskId">
  <div class="px-8 py-5 space-y-5">
    <div>
      <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">Title</label>
      <input id="fTitle" placeholder="Short descriptive title..." class="w-full px-4 py-3 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition font-medium">
    </div>
    <div>
      <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">Description</label>
      <textarea id="fDesc" rows="4" placeholder="What needs to be done..." class="w-full px-4 py-3 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition resize-y leading-relaxed"></textarea>
    </div>
    <div>
      <label class="block text-xs font-bold text-purple-400 uppercase tracking-wider mb-1.5">&#x1F916; Prompt (for Copilot / AI)</label>
      <textarea id="fPrompt" rows="4" placeholder="Paste your AI prompt here..." class="w-full px-4 py-3 text-sm border border-purple-200 rounded-xl focus:ring-2 focus:ring-purple-500 focus:border-purple-500 outline-none transition resize-y font-mono text-xs bg-purple-50/30 leading-relaxed"></textarea>
    </div>
    <div class="grid grid-cols-3 gap-4">
      <div>
        <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">Priority</label>
        <select id="fPriority" class="w-full px-4 py-3 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">
          <option value="low">&#x1F7E2; Low</option><option value="medium" selected>&#x1F7E1; Medium</option><option value="high">&#x1F7E0; High</option><option value="critical">&#x1F534; Critical</option>
        </select>
      </div>
      <div>
        <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">Bucket</label>
        <select id="fBucket" class="w-full px-4 py-3 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">__BUCKET_OPTIONS__</select>
      </div>
      <div>
        <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">Est. Time</label>
        <input id="fTime" placeholder="e.g. 2h, 30min" class="w-full px-4 py-3 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">
      </div>
    </div>
    <div class="grid grid-cols-2 gap-4">
      <div>
        <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">Application</label>
        <select id="fApp" class="w-full px-4 py-3 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition"><option value="">&#x2014; none &#x2014;</option></select>
      </div>
      <div>
        <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">Tags (comma-separated)</label>
        <input id="fTags" placeholder="refactor, security, ui" class="w-full px-4 py-3 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">
      </div>
    </div>
    <div>
      <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">App Directory</label>
      <input id="fDir" placeholder="~/Documents/Coding_space-Python/..." class="w-full px-4 py-3 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition font-mono text-xs">
    </div>
    <div>
      <label class="block text-xs font-bold text-emerald-500 uppercase tracking-wider mb-1.5">&#x1F4AC; Notes / Execution Log</label>
      <textarea id="fComment" rows="6" placeholder="Detailed notes on what was done, how, results, links to files..." class="w-full px-4 py-3 text-sm border border-emerald-200 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 outline-none transition resize-y bg-emerald-50/30 leading-relaxed"></textarea>
    </div>
    <div class="flex items-center gap-4 pt-1">
      <label class="flex items-center gap-2 cursor-pointer select-none">
        <input type="checkbox" id="fDone" class="w-5 h-5 rounded border-slate-300 text-emerald-600 focus:ring-emerald-500 transition">
        <span class="text-sm font-semibold text-emerald-600">Mark as Done</span>
      </label>
    </div>
  </div>
  <div class="sticky bottom-0 bg-white z-10 px-8 py-4 border-t border-slate-100 flex gap-3 justify-end rounded-b-2xl">
    <button class="px-5 py-2.5 text-sm font-medium text-slate-500 hover:bg-slate-50 rounded-xl border border-slate-200 transition" onclick="closeModal()">Cancel</button>
    <button class="px-8 py-2.5 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl shadow-lg shadow-blue-500/20 transition" onclick="saveTask()">Save</button>
  </div>
</div></div>

<!-- APP MODAL -->
<div class="fixed inset-0 bg-black/40 backdrop-blur-sm z-[200] hidden items-center justify-center" id="appModal">
<div class="bg-white rounded-2xl shadow-2xl w-[440px] max-w-[92vw] max-h-[80vh] overflow-y-auto p-8">
  <div class="flex items-center justify-between mb-6">
    <h2 class="text-xl font-bold text-slate-900">Applications</h2>
    <button onclick="closeAppModal()" class="w-8 h-8 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-400 hover:text-slate-600 transition">
      <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>
  </div>
  <div class="flex gap-2 mb-4">
    <input id="newAppName" placeholder="New application..." class="flex-1 px-4 py-2.5 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">
    <button onclick="addApp()" class="px-4 py-2.5 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition">Add</button>
  </div>
  <div id="appList" class="space-y-1"></div>
</div></div>

<!-- FILES PANEL (slide-over from right) -->
<div id="filesPanel" class="fixed inset-0 z-[190] hidden">
  <div class="absolute inset-0 bg-black/20 backdrop-blur-sm" onclick="toggleFilesPanel()"></div>
  <div class="absolute right-0 top-0 bottom-0 w-[380px] max-w-[90vw] bg-white shadow-2xl flex flex-col">
    <div class="px-6 py-5 border-b border-slate-100 flex items-center justify-between">
      <h2 class="text-lg font-bold text-slate-900">Files</h2>
      <button onclick="toggleFilesPanel()" class="w-8 h-8 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-400 hover:text-slate-600 transition">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    </div>
    <div class="px-6 py-4 border-b border-slate-100">
      <label class="flex items-center gap-3 px-4 py-3 border-2 border-dashed border-slate-200 rounded-xl hover:border-blue-400 hover:bg-blue-50/30 cursor-pointer transition">
        <svg class="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"/></svg>
        <span class="text-sm font-medium text-slate-500">Upload file...</span>
        <input type="file" class="hidden" id="fileUploadInput" onchange="uploadFile()">
      </label>
    </div>
    <div id="filesList" class="flex-1 overflow-y-auto p-4 space-y-2"></div>
  </div>
</div>

<script>
var S={tasks:[],apps:[]};
var BUCKETS=__BUCKETS_JSON__;
var LABELS=__LABELS_JSON__;
var COLORS=__COLORS_JSON__;
var SORT_STATE={};
var SHOW_ARCHIVED={};
var APP_FILTER=[];  // empty = show all

var PRIO_CFG={
  critical:{label:'Critical',icon:'\ud83d\udd34',bg:'bg-red-50',text:'text-red-600',border:'border-red-100',ring:'ring-red-500/20'},
  high:{label:'High',icon:'\ud83d\udfe0',bg:'bg-amber-50',text:'text-amber-600',border:'border-amber-100',ring:'ring-amber-500/20'},
  medium:{label:'Medium',icon:'\ud83d\udfe1',bg:'bg-yellow-50',text:'text-yellow-600',border:'border-yellow-100',ring:'ring-yellow-500/20'},
  low:{label:'Low',icon:'\ud83d\udfe2',bg:'bg-emerald-50',text:'text-emerald-600',border:'border-emerald-100',ring:'ring-emerald-500/20'}
};
var PRIO_ORD={critical:0,high:1,medium:2,low:3};

function load(){
  fetch('/api/tasks').then(function(r){return r.json()}).then(function(d){S=d;_lastHash=_taskHash(d.tasks||d);render()}).catch(function(e){console.error(e);render()});
}

// ── Filter by App (multiselect) ──
function toggleFilter(){
  document.getElementById('filterDrop').classList.toggle('hidden');
}
function buildFilter(){
  var drop=document.getElementById('filterDrop');
  var apps=(S.apps||[]).slice().sort();
  var h='<label class="flex items-center gap-2 px-3 py-1.5 hover:bg-slate-50 cursor-pointer text-sm"><input type="checkbox" onchange="setFilter()" class="appFilterCb rounded text-blue-600" value="" '+(APP_FILTER.length===0?'checked':'')+'>All Apps</label>';
  apps.forEach(function(a){
    h+='<label class="flex items-center gap-2 px-3 py-1.5 hover:bg-slate-50 cursor-pointer text-sm"><input type="checkbox" onchange="setFilter()" class="appFilterCb" value="'+esc(a)+'" '+(APP_FILTER.indexOf(a)>=0?'checked':'')+'>'+esc(a)+'</label>';
  });
  // Also add "No app" option
  h+='<label class="flex items-center gap-2 px-3 py-1.5 hover:bg-slate-50 cursor-pointer text-sm text-slate-400"><input type="checkbox" onchange="setFilter()" class="appFilterCb" value="__none__" '+(APP_FILTER.indexOf('__none__')>=0?'checked':'')+'>No app assigned</label>';
  drop.innerHTML=h;
}
function setFilter(){
  var cbs=document.querySelectorAll('.appFilterCb');
  var sel=[];
  cbs.forEach(function(cb){if(cb.checked && cb.value) sel.push(cb.value)});
  if(sel.length===0) APP_FILTER=[];
  else APP_FILTER=sel;
  document.getElementById('filterLabel').textContent=APP_FILTER.length?APP_FILTER.length+' selected':'All Apps';
  render();
}
document.addEventListener('click',function(e){
  var w=document.getElementById('filterWrap');
  if(w && !w.contains(e.target)) document.getElementById('filterDrop').classList.add('hidden');
});

function matchFilter(t){
  if(!APP_FILTER.length) return true;
  if(!t.app && APP_FILTER.indexOf('__none__')>=0) return true;
  return APP_FILTER.indexOf(t.app)>=0;
}

function render(){
  var b=document.getElementById('board');b.innerHTML='';
  var allTasks=(S.tasks||[]).filter(matchFilter);
  var totalAll=(S.tasks||[]).length;
  var total=allTasks.length;
  var doneCnt=allTasks.filter(function(t){return t.bucket==='done'}).length;
  var critCnt=allTasks.filter(function(t){return t.priority==='critical'&&t.bucket!=='done'}).length;
  var prodCnt=allTasks.filter(function(t){return t.bucket==='for-production'}).length;
  var ipCnt=allTasks.filter(function(t){return t.in_progress}).length;
  var bar=document.getElementById('statsBar');
  bar.innerHTML='<div class="flex items-center gap-1.5 text-xs font-medium text-slate-400"><span class="w-2 h-2 rounded-full bg-slate-300"></span>'+total+(total!==totalAll?' / '+totalAll:'')+' tasks</div>'
    +'<div class="flex items-center gap-1.5 text-xs font-medium text-emerald-500"><span class="w-2 h-2 rounded-full bg-emerald-400"></span>'+doneCnt+' done</div>'
    +(critCnt?'<div class="flex items-center gap-1.5 text-xs font-medium text-red-500"><span class="w-2 h-2 rounded-full bg-red-400 animate-pulse"></span>'+critCnt+' critical</div>':'')
    +(prodCnt?'<div class="flex items-center gap-1.5 text-xs font-medium text-amber-500"><span class="w-2 h-2 rounded-full bg-amber-400"></span>'+prodCnt+' in production</div>':'')
    +(ipCnt?'<div class="flex items-center gap-1.5 text-xs font-medium text-blue-500"><span class="w-2 h-2 rounded-full bg-blue-400 animate-pulse"></span>'+ipCnt+' in progress</div>':'');

  BUCKETS.forEach(function(bk){
    var rawTasks=allTasks.filter(function(t){return t.bucket===bk});
    var showArch=SHOW_ARCHIVED[bk]||false;
    var tasks=rawTasks.filter(function(t){return showArch||!t.archived});
    var archCnt=rawTasks.filter(function(t){return t.archived}).length;
    var ss=SORT_STATE[bk]||{field:'order',asc:true};
    tasks.sort(function(a,b){
      var f=ss.field;var mul=ss.asc?1:-1;
      if(f==='priority') return mul*(PRIO_ORD[a.priority||'medium']-PRIO_ORD[b.priority||'medium']);
      if(f==='created_at') return mul*((a.created_at||'')>(b.created_at||'')?1:-1);
      return mul*((a.order||999)-(b.order||999));
    });
    var col=document.createElement('div');
    col.className='min-w-[290px] max-w-[320px] flex-1 flex flex-col rounded-2xl border border-slate-200 bg-white shadow-sm max-h-[calc(100vh-8rem)]';

    var color=COLORS[bk]||'#64748b';
    var hd=document.createElement('div');
    hd.className='px-4 py-3.5 border-b border-slate-100';
    var sortIco=ss.asc?'\u25b2':'\u25bc';
    var sortLabel={order:'Ord.',priority:'Prio',created_at:'Date'}[ss.field]||'Ord.';
    hd.innerHTML='<div class="flex items-center justify-between mb-1"><div class="flex items-center gap-2.5"><span class="w-2.5 h-2.5 rounded-full shadow-sm" style="background:'+color+'"></span><span class="text-sm font-semibold text-slate-700">'+LABELS[bk]+'</span></div><span class="text-xs font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-500">'+tasks.length+'</span></div>'
      +'<div class="flex items-center gap-1 mt-1">'
      +'<button onclick="cycleSort(\''+bk+'\')" class="text-[10px] px-1.5 py-0.5 rounded bg-slate-50 hover:bg-slate-100 text-slate-500 font-medium transition" title="Sort">'+sortIco+' '+sortLabel+'</button>'
      +(archCnt?'<button onclick="toggleArchive(\''+bk+'\')" class="text-[10px] px-1.5 py-0.5 rounded '+(showArch?'bg-amber-100 text-amber-600':'bg-slate-50 text-slate-400')+' hover:bg-slate-100 font-medium transition" title="Archive">\ud83d\udce6 '+archCnt+'</button>':'')
      +'</div>';
    col.appendChild(hd);

    var body=document.createElement('div');
    body.className='p-2.5 flex-1 overflow-y-auto space-y-2 min-h-[60px] rounded-b-2xl transition-colors duration-200';
    body.setAttribute('data-bucket',bk);
    body.addEventListener('dragover',function(e){e.preventDefault();body.classList.add('drag-over')});
    body.addEventListener('dragleave',function(){body.classList.remove('drag-over')});
    body.addEventListener('drop',function(e){e.preventDefault();body.classList.remove('drag-over');onDrop(e,bk)});

    if(!tasks.length){
      body.innerHTML='<div class="text-center py-8 text-slate-300 text-xs font-medium">Drag tasks here...</div>';
    } else {
      tasks.forEach(function(t){body.appendChild(mkCard(t))});
    }
    col.appendChild(body);b.appendChild(col);
  });
  updAppSel();
  buildFilter();
}

function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}

function mkCard(t){
  var c=document.createElement('div');
  var archCls=t.archived?' opacity-50':'';
  var doneCls=t.done?' border-l-2 border-l-emerald-400':'';
  // #9 Red border if no prompt
  var noPrompt=(!t.prompt||!t.prompt.trim())?' no-prompt-border':'';
  // #3 Sprint glow for for-production tasks
  var sprintCls=(t.bucket==='for-production'&&!t.in_progress)?' sprint-glow':'';
  // In-progress glow — agent is actively working on this task
  var inProgressCls=t.in_progress?' in-progress-glow':'';
  // #3 Just-done glow for for-tests-confirm tasks (recently completed by agent)
  var justDoneCls=((t.bucket==='for-tests-confirm')&&t.comment&&t.comment.indexOf('\u2705')>=0)?' just-done-glow':'';
  c.className='group relative p-3.5 rounded-xl border border-slate-150 bg-white hover:shadow-md hover:border-slate-200 cursor-grab transition-all duration-150 fade-card'+archCls+doneCls+noPrompt+sprintCls+inProgressCls+justDoneCls;
  c.draggable=true;c.setAttribute('data-id',t.id);
  c.addEventListener('dragstart',function(e){e.dataTransfer.setData('text/plain',t.id);c.classList.add('card-drag')});
  c.addEventListener('dragend',function(){c.classList.remove('card-drag')});

  var p=PRIO_CFG[t.priority]||PRIO_CFG.medium;
  var h='<div class="absolute top-2.5 right-2.5 hidden group-hover:flex gap-1">';
  h+='<button onclick="toggleDone(\''+t.id+'\')" class="w-7 h-7 rounded-lg bg-slate-50 '+(t.done?'bg-emerald-50 text-emerald-600':'hover:bg-emerald-50 hover:text-emerald-600 text-slate-400')+' flex items-center justify-center transition text-xs" title="Toggle Done">'+(t.done?'\u2705':'\u2b1c')+'</button>';
  h+='<button onclick="toggleArchived(\''+t.id+'\')" class="w-7 h-7 rounded-lg bg-slate-50 hover:bg-amber-50 hover:text-amber-600 flex items-center justify-center text-slate-400 transition text-xs" title="Archive">\ud83d\udce6</button>';
  h+='<button onclick="editTask(\''+t.id+'\')" class="w-7 h-7 rounded-lg bg-slate-50 hover:bg-blue-50 hover:text-blue-600 flex items-center justify-center text-slate-400 transition text-xs" title="Edit"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z"/></svg></button>';
  h+='<button onclick="delTask(\''+t.id+'\')" class="w-7 h-7 rounded-lg bg-slate-50 hover:bg-red-50 hover:text-red-500 flex items-center justify-center text-slate-400 transition text-xs" title="Delete"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/></svg></button>';
  h+='</div>';

  // Sprint / in-progress / done badges
  if(t.in_progress) h+='<span class="text-[9px] font-bold text-blue-600 bg-blue-50 px-1.5 py-0.5 rounded uppercase tracking-wider mb-1 inline-block">\ud83d\udd27 In Progress</span> ';
  if(t.bucket==='for-production'&&!t.in_progress) h+='<span class="text-[9px] font-bold text-amber-600 bg-amber-50 px-1.5 py-0.5 rounded uppercase tracking-wider mb-1 inline-block">\u26a1 In Sprint</span> ';
  if(t.done) h+='<span class="text-[9px] font-bold text-emerald-600 bg-emerald-50 px-1.5 py-0.5 rounded uppercase tracking-wider mb-1 inline-block">\u2705 Done</span> ';

  h+='<div class="text-[13px] font-semibold text-slate-800 leading-snug pr-14 mb-1.5'+(t.done?' line-through opacity-60':'')+'">'+esc(t.title||'Untitled')+'</div>';
  if(t.description) h+='<div class="text-xs text-slate-400 leading-relaxed mb-2.5 line-clamp-2">'+esc(t.description)+'</div>';

  var tags='';
  (t.tags||[]).forEach(function(g){tags+='<span class="text-[10px] font-medium px-2 py-0.5 rounded-md bg-slate-100 text-slate-500">'+esc(g)+'</span>'});
  if(t.app) tags+='<span class="text-[10px] font-medium px-2 py-0.5 rounded-md bg-blue-50 text-blue-600">'+esc(t.app)+'</span>';
  if(t.prompt) tags+='<span class="text-[10px] font-medium px-2 py-0.5 rounded-md bg-purple-50 text-purple-600">\ud83e\udd16 Prompt</span>';
  if(tags) h+='<div class="flex flex-wrap gap-1 mb-2.5">'+tags+'</div>';

  h+='<div class="flex items-center justify-between">';
  h+='<span class="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-md ring-1 '+p.ring+' '+p.bg+' '+p.text+'">'+p.icon+' '+p.label+'</span>';
  var right='';
  if(t.estimated_time) right+='<span class="text-[10px] font-medium text-violet-500">\u23f1 '+esc(t.estimated_time)+'</span>';
  right+='<span class="text-[10px] opacity-50">'+(t.source==='copilot'?'\ud83e\udd16':'\ud83d\udc64')+'</span>';
  h+='<div class="flex items-center gap-2">'+right+'</div></div>';

  if(t.app_directory) h+='<div class="mt-2 text-[10px] font-mono text-slate-400 bg-slate-50 px-2 py-1 rounded-lg truncate">\ud83d\udcc1 '+esc(t.app_directory)+'</div>';
  // #8 Longer note — show more, with scrollable area
  if(t.comment){
    var shortComment=t.comment.length>120?t.comment.substring(0,120)+'...':t.comment;
    h+='<div class="mt-2 text-[11px] text-emerald-700 font-medium leading-relaxed bg-emerald-50 px-2.5 py-2 rounded-lg cursor-pointer max-h-16 overflow-hidden hover:max-h-none transition-all" title="Click to expand" onclick="event.stopPropagation();this.classList.toggle(\'max-h-16\');this.classList.toggle(\'max-h-none\')">\ud83d\udcac '+esc(t.comment)+'</div>';
  }

  c.innerHTML=h;return c;
}

function onDrop(e,bucket){
  var id=e.dataTransfer.getData('text/plain');if(!id)return;
  var task=S.tasks.find(function(t){return t.id===id});if(task)task.bucket=bucket;
  var bt=S.tasks.filter(function(t){return t.bucket===bucket}).sort(function(a,b){return(a.order||999)-(b.order||999)});
  var ups=[];bt.forEach(function(t,i){t.order=i;ups.push({id:t.id,bucket:bucket,order:i})});
  render();
  fetch('/api/reorder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({updates:ups})});
}

function openModal(id){
  var m=document.getElementById('taskModal');m.classList.remove('hidden');m.classList.add('flex');
  if(id){
    var t=S.tasks.find(function(x){return x.id===id});if(!t)return;
    document.getElementById('mTitle').textContent='Edit Task';
    document.getElementById('taskId').value=t.id;
    document.getElementById('fTitle').value=t.title||'';
    document.getElementById('fDesc').value=t.description||'';
    document.getElementById('fPrompt').value=t.prompt||'';
    document.getElementById('fPriority').value=t.priority||'medium';
    document.getElementById('fBucket').value=t.bucket||'manually-recommended';
    document.getElementById('fApp').value=t.app||'';
    document.getElementById('fTime').value=t.estimated_time||'';
    document.getElementById('fDir').value=t.app_directory||'';
    document.getElementById('fTags').value=(t.tags||[]).join(', ');
    document.getElementById('fComment').value=t.comment||'';
    document.getElementById('fDone').checked=!!t.done;
  }else{
    document.getElementById('mTitle').textContent='New Task';
    ['taskId','fTitle','fDesc','fPrompt','fTime','fDir','fTags','fComment'].forEach(function(x){document.getElementById(x).value=''});
    document.getElementById('fPriority').value='medium';
    document.getElementById('fBucket').value='manually-recommended';
    document.getElementById('fApp').value='';
    document.getElementById('fDone').checked=false;
  }
}
function closeModal(){var m=document.getElementById('taskModal');m.classList.add('hidden');m.classList.remove('flex')}
function editTask(id){openModal(id)}
function delTask(id){if(!confirm('Delete this task?'))return;fetch('/api/tasks/'+id,{method:'DELETE'}).then(load)}
function saveTask(){
  var id=document.getElementById('taskId').value;
  var body={title:document.getElementById('fTitle').value,description:document.getElementById('fDesc').value,prompt:document.getElementById('fPrompt').value,priority:document.getElementById('fPriority').value,bucket:document.getElementById('fBucket').value,app:document.getElementById('fApp').value,estimated_time:document.getElementById('fTime').value,app_directory:document.getElementById('fDir').value,tags:document.getElementById('fTags').value.split(',').map(function(s){return s.trim()}).filter(Boolean),comment:document.getElementById('fComment').value,done:document.getElementById('fDone').checked,source:'manual'};
  var url=id?'/api/tasks/'+id:'/api/tasks';
  var method=id?'PUT':'POST';
  fetch(url,{method:method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(){closeModal();load()});
}
function updAppSel(){
  var s=document.getElementById('fApp');var v=s.value;
  s.innerHTML='<option value="">\u2014 none \u2014</option>';
  (S.apps||[]).forEach(function(a){var o=document.createElement('option');o.value=a;o.textContent=a;if(a===v)o.selected=true;s.appendChild(o)});
}
function openAppModal(){var m=document.getElementById('appModal');m.classList.remove('hidden');m.classList.add('flex');renderApps()}
function closeAppModal(){var m=document.getElementById('appModal');m.classList.add('hidden');m.classList.remove('flex')}
function renderApps(){document.getElementById('appList').innerHTML=(S.apps||[]).map(function(a){return'<div class="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-slate-50 text-sm text-slate-700"><span class="w-2 h-2 rounded-full bg-blue-400"></span>'+esc(a)+'</div>'}).join('')}
function addApp(){var i=document.getElementById('newAppName');var n=i.value.trim();if(!n)return;fetch('/api/apps',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})}).then(function(){i.value='';load();renderApps()})}

function cycleSort(bk){
  var fields=['order','priority','created_at'];
  var ss=SORT_STATE[bk]||{field:'order',asc:true};
  var idx=fields.indexOf(ss.field);
  if(ss.asc){ss.asc=false}else{idx=(idx+1)%fields.length;ss.field=fields[idx];ss.asc=true}
  SORT_STATE[bk]=ss;render();
}
function toggleArchive(bk){SHOW_ARCHIVED[bk]=!SHOW_ARCHIVED[bk];render()}
function toggleDone(id){
  var t=S.tasks.find(function(x){return x.id===id});if(!t)return;
  t.done=!t.done;render();
  fetch('/api/tasks/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({done:t.done})});
}
function toggleArchived(id){
  var t=S.tasks.find(function(x){return x.id===id});if(!t)return;
  t.archived=!t.archived;render();
  fetch('/api/tasks/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({archived:t.archived})});
}

document.getElementById('taskModal').addEventListener('click',function(e){if(e.target===this)closeModal()});
document.getElementById('appModal').addEventListener('click',function(e){if(e.target===this)closeAppModal()});
document.addEventListener('keydown',function(e){if(e.key==='Escape'){closeModal();closeAppModal();var fp=document.getElementById('filesPanel');if(!fp.classList.contains('hidden'))fp.classList.add('hidden')}});

// ── File Management ──
function toggleFilesPanel(){
  var p=document.getElementById('filesPanel');
  if(p.classList.contains('hidden')){p.classList.remove('hidden');loadFiles()}
  else p.classList.add('hidden');
}
function loadFiles(){
  fetch('/api/files').then(function(r){return r.json()}).then(function(d){renderFiles(d.files||[])});
}
var PREVIEW_EXTS=['.html','.htm','.txt','.css','.csv','.json','.js','.pdf','.png','.jpg','.jpeg','.gif','.svg','.webp'];
function canPreview(name){var ext=name.substring(name.lastIndexOf('.')).toLowerCase();return PREVIEW_EXTS.indexOf(ext)>=0}
function previewFile(name){window.open('/api/files/'+encodeURIComponent(name)+'?preview=1','_blank')}
function renderFiles(files){
  var el=document.getElementById('filesList');
  if(!files.length){el.innerHTML='<div class="text-center py-8 text-slate-300 text-sm">No files yet</div>';return}
  el.innerHTML=files.map(function(f){
    var sz=f.size<1024?(f.size+' B'):f.size<1048576?((f.size/1024).toFixed(1)+' KB'):((f.size/1048576).toFixed(1)+' MB');
    var cp=canPreview(f.name);
    // File icon — different for previewable
    var ico=cp?'\ud83d\udc41\ufe0f':'<svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"/></svg>';
    var icoBox=cp
      ?'<div class="w-9 h-9 bg-emerald-50 rounded-lg flex items-center justify-center text-emerald-500 flex-shrink-0 cursor-pointer hover:bg-emerald-100 transition" onclick="previewFile(\''+esc(f.name)+'\')" title="Click to preview">'+ico+'</div>'
      :'<div class="w-9 h-9 bg-blue-50 rounded-lg flex items-center justify-center text-blue-500 flex-shrink-0">'+ico+'</div>';
    var shareBtn='<button onclick="togglePublic(\''+esc(f.name)+'\')" class="share-btn w-7 h-7 rounded-lg bg-slate-50 hover:bg-indigo-50 hover:text-indigo-600 flex items-center justify-center text-slate-400 transition" title="Share public link" data-fname="'+esc(f.name)+'"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m9.86-2.54a4.5 4.5 0 00-1.242-7.244l-4.5-4.5a4.5 4.5 0 00-6.364 6.364L4.34 8.798"/></svg></button>';
    return '<div class="flex items-center gap-3 p-3 rounded-xl border border-slate-100 hover:border-slate-200 hover:bg-slate-50 transition group">'
      +icoBox
      +'<div class="flex-1 min-w-0"><div class="text-sm font-medium text-slate-700 truncate'+(cp?' cursor-pointer hover:text-emerald-600':'')+'"'+(cp?' onclick="previewFile(\''+esc(f.name)+'\')"':'')+'>'+esc(f.name)+'</div><div class="text-[10px] text-slate-400">'+sz+(cp?' \u00b7 <span class="text-emerald-500">previewable</span>':'')+'</div></div>'
      +shareBtn
      +'<a href="'+f.url+'" class="w-7 h-7 rounded-lg bg-slate-50 hover:bg-blue-50 hover:text-blue-600 flex items-center justify-center text-slate-400 transition" title="Download"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"/></svg></a>'
      +'<button onclick="deleteFile(\''+esc(f.name)+'\')" class="w-7 h-7 rounded-lg bg-slate-50 hover:bg-red-50 hover:text-red-500 hidden group-hover:flex items-center justify-center text-slate-400 transition" title="Delete"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/></svg></button>'
      +'</div>';
  }).join('');
}
function uploadFile(){
  var inp=document.getElementById('fileUploadInput');
  if(!inp.files.length)return;
  var fd=new FormData();fd.append('file',inp.files[0]);
  fetch('/api/files',{method:'POST',body:fd}).then(function(){inp.value='';loadFiles()});
}
function deleteFile(name){
  if(!confirm('Delete file "'+name+'"?'))return;
  fetch('/api/files/'+encodeURIComponent(name),{method:'DELETE'}).then(loadFiles);
}
function togglePublic(name){
  // Check current public status via GET /api/files/<name>/public
  fetch('/api/files/'+encodeURIComponent(name)+'/public')
  .then(function(r){return r.json()})
  .then(function(d){
    if(d.public){
      if(confirm('Unpublish "'+name+'"? Public link will stop working.')){
        fetch('/api/files/'+encodeURIComponent(name)+'/public',{method:'DELETE'})
        .then(function(){loadFiles();alert('File unpublished.')});
      }
    }else{
      fetch('/api/files/'+encodeURIComponent(name)+'/public',{method:'POST'})
      .then(function(r){return r.json()})
      .then(function(d){
        loadFiles();
        var url=location.origin+(d.public_url||'');
        prompt('Public link (copied to clipboard):',url);
        if(navigator.clipboard)navigator.clipboard.writeText(url);
      });
    }
  });
}

load();

// ── Live polling — detect changes, re-render smoothly ──
var POLL_INTERVAL=5000;
var _lastHash='';
function _taskHash(tasks){
  return (tasks||[]).map(function(t){
    return t.id+'|'+t.bucket+'|'+(t.in_progress?1:0)+'|'+(t.done?1:0)+'|'+(t.comment||'').length;
  }).sort().join(';');
}
function poll(){
  fetch('/api/tasks').then(function(r){return r.json()}).then(function(d){
    var h=_taskHash(d.tasks||d);
    if(h!==_lastHash){
      _lastHash=h;
      S=d;
      render();
    }
  }).catch(function(){});
}
setInterval(poll,POLL_INTERVAL);
</script></body></html>"""


# ══════════════════════════════════════════════
# ANALYTICS BLOCK DESIGNER
# ══════════════════════════════════════════════

def load_analytics():
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blob = bucket.blob("analytics.json")
        if blob.exists():
            return json.loads(blob.download_as_text())
    except Exception as exc:
        log.error("GCS analytics read error: %s", exc)
    return {"dashboards": [], "sets": []}


def save_analytics(data):
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blob = bucket.blob("analytics.json")
        blob.upload_from_string(
            json.dumps(data, ensure_ascii=False, indent=2),
            content_type="application/json",
        )
        return True
    except Exception as exc:
        log.error("GCS analytics write error: %s", exc)
        return False


@app.route("/api/analytics", methods=["GET"])
@login_required
def api_get_analytics():
    return jsonify(load_analytics())


@app.route("/api/analytics", methods=["POST"])
@login_required
def api_save_analytics():
    data = request.get_json(force=True)
    if save_analytics(data):
        return jsonify({"ok": True})
    return jsonify({"error": "save failed"}), 500


@app.route("/analytics")
@login_required
def analytics_page():
    resp = make_response(ANALYTICS_PAGE)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# ──────────────────────────────────────────────
# ANALYTICS PAGE HTML
# ──────────────────────────────────────────────
ANALYTICS_PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KanGo &mdash; Analytics Designer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{fontFamily:{outfit:['Outfit','sans-serif']}}}}</script>
<style>
body{font-family:'Outfit',sans-serif}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:10px}
.block-ghost{border:2px dashed rgba(99,102,241,0.4);background:rgba(99,102,241,0.03);border-radius:12px}
.block-card{transition:box-shadow .15s,transform .15s}
.block-card:hover{box-shadow:0 8px 25px -5px rgba(0,0,0,0.08);transform:translateY(-1px)}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.fade-in{animation:fadeIn .3s ease-out}
.drag-over-row{background:rgba(99,102,241,0.04);border-radius:12px}
</style>
</head>
<body class="bg-slate-50 font-outfit min-h-screen">

<!-- TOP BAR -->
<header class="bg-white border-b border-slate-200 sticky top-0 z-50">
<div class="flex items-center justify-between px-6 h-16">
  <div class="flex items-center gap-3">
    <a href="/" class="flex items-center gap-3 hover:opacity-80 transition">
      <div class="w-9 h-9 bg-gradient-to-br from-violet-600 to-indigo-600 rounded-xl flex items-center justify-center text-white text-lg shadow-lg shadow-violet-500/20">&#x1F4CA;</div>
      <div>
        <h1 class="text-lg font-bold text-slate-900 leading-none">KanGo</h1>
        <p class="text-[10px] text-slate-400 font-medium tracking-wide uppercase">Analytics Designer</p>
      </div>
    </a>
  </div>
  <div class="flex items-center gap-2">
    <!-- Set selector -->
    <select id="setSelect" onchange="switchSet(this.value)" class="px-3 py-2 text-sm border border-slate-200 rounded-xl text-slate-600 font-medium bg-white"></select>
    <button onclick="addSet()" class="px-3 py-2.5 text-slate-500 hover:text-violet-600 hover:bg-violet-50 text-sm font-medium rounded-xl border border-slate-200 transition-all" title="New dashboard set">
      <svg class="w-4 h-4 inline" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 10.5v6m3-3H9m4.06-7.19l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z"/></svg>
      Set
    </button>
    <span class="text-slate-300">|</span>
    <!-- Page tabs -->
    <div id="pageTabs" class="flex items-center gap-1"></div>
    <button onclick="addPage()" class="px-3 py-2.5 text-slate-500 hover:text-violet-600 hover:bg-violet-50 text-sm font-medium rounded-xl border border-slate-200 transition-all" title="Add page">
      <svg class="w-4 h-4 inline" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>
      Page
    </button>
    <span class="text-slate-300">|</span>
    <button onclick="addRow()" class="inline-flex items-center gap-1.5 px-4 py-2.5 bg-violet-600 hover:bg-violet-700 text-white text-sm font-semibold rounded-xl shadow-lg shadow-violet-500/20 transition-all">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>
      Row
    </button>
    <button onclick="saveAll()" class="inline-flex items-center gap-1.5 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-semibold rounded-xl shadow-lg shadow-emerald-500/20 transition-all">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M17.593 3.322c1.1.128 1.907 1.077 1.907 2.185V21L12 17.25 4.5 21V5.507c0-1.108.806-2.057 1.907-2.185a48.507 48.507 0 0111.186 0z"/></svg>
      Save
    </button>
    <a href="/" class="px-3 py-2.5 text-slate-500 hover:text-slate-700 hover:bg-slate-50 text-sm font-medium rounded-xl border border-slate-200 transition-all">Board</a>
    <a href="/files" class="px-3 py-2.5 text-slate-500 hover:text-slate-700 hover:bg-slate-50 text-sm font-medium rounded-xl border border-slate-200 transition-all">Files</a>
  </div>
</div>
</header>

<!-- CANVAS -->
<div class="p-6 max-w-[1600px] mx-auto" id="canvas"></div>

<!-- BLOCK EDIT MODAL -->
<div class="fixed inset-0 bg-black/40 backdrop-blur-sm z-[200] hidden items-center justify-center" id="blockModal">
<div class="bg-white rounded-2xl shadow-2xl w-[560px] max-w-[94vw] max-h-[92vh] overflow-y-auto">
  <div class="px-6 pt-5 pb-4 border-b border-slate-100 flex items-center justify-between">
    <h2 class="text-lg font-bold text-slate-900">Edit Block</h2>
    <button onclick="closeBlockModal()" class="w-8 h-8 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-400">&#x2715;</button>
  </div>
  <div class="p-6 space-y-4">
    <div>
      <label class="block text-xs font-semibold text-slate-500 mb-1">Title</label>
      <input id="bm_title" class="w-full px-3 py-2 border rounded-xl text-sm" placeholder="e.g. Revenue by Channel">
    </div>
    <div class="grid grid-cols-2 gap-4">
      <div>
        <label class="block text-xs font-semibold text-slate-500 mb-1">Data Type</label>
        <select id="bm_dataType" class="w-full px-3 py-2 border rounded-xl text-sm">
          <option value="kpi">KPI / Metric</option>
          <option value="timeseries">Time Series</option>
          <option value="categorical">Categorical / Bar</option>
          <option value="comparison">Comparison</option>
          <option value="distribution">Distribution / Pie</option>
          <option value="table">Table / Grid</option>
          <option value="geo">Geographic</option>
          <option value="funnel">Funnel</option>
          <option value="text">Text / Commentary</option>
          <option value="custom">Custom</option>
        </select>
      </div>
      <div>
        <label class="block text-xs font-semibold text-slate-500 mb-1">View Type</label>
        <select id="bm_viewType" class="w-full px-3 py-2 border rounded-xl text-sm">
          <option value="line">Line Chart</option>
          <option value="bar">Bar Chart</option>
          <option value="horizontalBar">Horizontal Bar</option>
          <option value="pie">Pie / Donut</option>
          <option value="area">Area Chart</option>
          <option value="scatter">Scatter Plot</option>
          <option value="radar">Radar</option>
          <option value="number">Big Number (KPI)</option>
          <option value="table">Data Table</option>
          <option value="text">Text Block</option>
          <option value="stacked">Stacked Bar</option>
          <option value="gauge">Gauge</option>
        </select>
      </div>
    </div>
    <div class="grid grid-cols-2 gap-4">
      <div>
        <label class="block text-xs font-semibold text-slate-500 mb-1">Width (1-4 columns)</label>
        <select id="bm_cols" class="w-full px-3 py-2 border rounded-xl text-sm">
          <option value="1">1/4 width</option>
          <option value="2">2/4 width</option>
          <option value="3">3/4 width</option>
          <option value="4">Full width</option>
        </select>
      </div>
      <div>
        <label class="block text-xs font-semibold text-slate-500 mb-1">Height (1-4 units)</label>
        <select id="bm_rows" class="w-full px-3 py-2 border rounded-xl text-sm">
          <option value="1">1x (compact)</option>
          <option value="2">2x (standard)</option>
          <option value="3">3x (tall)</option>
          <option value="4">4x (extra tall)</option>
        </select>
      </div>
    </div>
    <div>
      <label class="block text-xs font-semibold text-slate-500 mb-1">Description / AI Prompt</label>
      <textarea id="bm_desc" rows="3" class="w-full px-3 py-2 border rounded-xl text-sm" placeholder="Describe what this block should show. Copilot will use this to generate the StratosX view..."></textarea>
    </div>
    <div>
      <label class="block text-xs font-semibold text-slate-500 mb-1">Color Accent</label>
      <div class="flex gap-2" id="bm_colors"></div>
    </div>
  </div>
  <div class="px-6 pb-5 flex justify-end gap-2">
    <button onclick="closeBlockModal()" class="px-4 py-2 text-sm text-slate-500 hover:bg-slate-50 rounded-xl border">Cancel</button>
    <button onclick="deleteBlock()" class="px-4 py-2 text-sm text-red-500 hover:bg-red-50 rounded-xl border border-red-200">Delete</button>
    <button onclick="saveBlock()" class="px-4 py-2 text-sm text-white bg-violet-600 hover:bg-violet-700 rounded-xl font-semibold shadow">Save Block</button>
  </div>
</div>
</div>

<script>
/* ── State ── */
var DATA={dashboards:[],sets:[]};
var currentSetIdx=0;
var currentPageIdx=0;
var editBlockRef=null; // {rowIdx, blockIdx}
var COLORS=['#6366f1','#3b82f6','#22c55e','#f59e0b','#ef4444','#ec4899','#8b5cf6','#14b8a6','#f97316','#64748b'];
var UNIT_H=120; // 1 height unit in px

/* ── Init ── */
fetch('/api/analytics',{credentials:'same-origin'})
  .then(function(r){return r.json()})
  .then(function(d){
    DATA=d||{dashboards:[],sets:[]};
    if(!DATA.sets||!DATA.sets.length){seedSampleData();}
    renderSetSelect();
    renderPageTabs();
    renderCanvas();
  });

function seedSampleData(){
  DATA.sets=[
    {name:'eCommerce Performance',pages:[
      {name:'Overview',rows:[
        {type:'blocks',blocks:[
          {title:'Total Revenue',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'Total eCommerce revenue YTD across all channels',color:'#22c55e',sampleValue:'€24.7M',sampleDelta:'+12.3%'},
          {title:'Online Orders',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'Total orders count YTD',color:'#3b82f6',sampleValue:'1.24M',sampleDelta:'+8.1%'},
          {title:'Avg Order Value',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'Average order value in EUR',color:'#8b5cf6',sampleValue:'€19.92',sampleDelta:'-2.1%'},
          {title:'Conversion Rate',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'Site-wide conversion rate',color:'#f59e0b',sampleValue:'3.47%',sampleDelta:'+0.3pp'}
        ]},
        {type:'text',text:'Channel Performance — Q1 2026 vs Q1 2025'},
        {type:'blocks',blocks:[
          {title:'Revenue by Channel',dataType:'categorical',viewType:'bar',cols:2,rows:2,desc:'Revenue breakdown: Amazon, DTC, Walmart, Instacart, Other marketplaces. Show YoY comparison.',color:'#6366f1',
           sampleData:{labels:['Amazon','DTC','Walmart','Instacart','Other'],datasets:[{label:'Q1 2026',data:[8.2,6.1,4.8,3.1,2.5],backgroundColor:'rgba(99,102,241,0.7)'},{label:'Q1 2025',data:[7.1,5.8,4.2,2.3,2.6],backgroundColor:'rgba(99,102,241,0.25)'}]}},
          {title:'Monthly Revenue Trend',dataType:'timeseries',viewType:'line',cols:2,rows:2,desc:'Monthly revenue trend for last 12 months with forecast line for next 3 months',color:'#3b82f6',
           sampleData:{labels:['Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec','Jan','Feb','Mar'],datasets:[{label:'Revenue (€M)',data:[1.8,1.9,2.1,2.0,2.3,2.2,2.5,2.4,2.8,2.6,2.7,2.9],borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,0.08)',fill:true,tension:0.3}]}}
        ]},
        {type:'blocks',blocks:[
          {title:'Traffic Sources',dataType:'distribution',viewType:'pie',cols:1,rows:2,desc:'Traffic distribution: Organic Search, Paid Search, Social, Direct, Email, Referral',color:'#ec4899',
           sampleData:{labels:['Organic','Paid','Social','Direct','Email','Referral'],datasets:[{data:[35,25,15,12,8,5],backgroundColor:['#6366f1','#3b82f6','#ec4899','#22c55e','#f59e0b','#64748b']}]}},
          {title:'Top 10 SKUs by Revenue',dataType:'table',viewType:'table',cols:3,rows:2,desc:'Table: SKU, Product Name, Revenue, Units Sold, Margin %. Sorted by revenue desc. Highlight top 3.',color:'#14b8a6',
           sampleTable:{headers:['#','SKU','Product','Revenue','Units','Margin'],rows:[['1','SKU-4821','Premium Dark Chocolate 200g','€847K','42.3K','34.2%'],['2','SKU-1093','Organic Protein Bar 12pk','€721K','36.1K','28.7%'],['3','SKU-7756','Kids Vitamin Gummies','€634K','52.8K','41.3%'],['4','SKU-2214','Plant Milk Oat 1L','€589K','98.2K','22.1%'],['5','SKU-3390','Greek Yogurt Mix 500g','€512K','64.1K','31.5%']]}}
        ]}
      ]},
      {name:'Retail Media',rows:[
        {type:'blocks',blocks:[
          {title:'Media Spend',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'Total retail media spend YTD',color:'#ef4444',sampleValue:'€3.1M',sampleDelta:'+22%'},
          {title:'ROAS',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'Return on ad spend — blended',color:'#22c55e',sampleValue:'4.2x',sampleDelta:'+0.3x'},
          {title:'Impressions',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'Total ad impressions',color:'#3b82f6',sampleValue:'287M',sampleDelta:'+31%'},
          {title:'CPC Avg',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'Average cost per click across platforms',color:'#f59e0b',sampleValue:'€0.42',sampleDelta:'-8%'}
        ]},
        {type:'blocks',blocks:[
          {title:'ROAS by Platform',dataType:'comparison',viewType:'horizontalBar',cols:2,rows:2,desc:'ROAS comparison across Amazon Ads, Walmart Connect, Instacart Ads, Criteo, Google Shopping',color:'#8b5cf6',
           sampleData:{labels:['Amazon Ads','Walmart Connect','Instacart Ads','Criteo','Google Shopping'],datasets:[{label:'ROAS',data:[4.8,3.9,5.2,3.1,3.6],backgroundColor:['#6366f1','#3b82f6','#22c55e','#f59e0b','#ef4444']}]}},
          {title:'Spend vs Revenue Trend',dataType:'timeseries',viewType:'area',cols:2,rows:2,desc:'Monthly media spend overlaid with attributed revenue. Dual Y-axis.',color:'#3b82f6',
           sampleData:{labels:['Oct','Nov','Dec','Jan','Feb','Mar'],datasets:[{label:'Spend (€K)',data:[420,480,520,510,490,530],borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,0.08)',fill:true,tension:0.3},{label:'Attributed Rev (€K)',data:[1890,2160,2340,2290,2200,2380],borderColor:'#22c55e',backgroundColor:'rgba(34,197,94,0.08)',fill:true,tension:0.3}]}}
        ]},
        {type:'text',text:'Campaign Performance Breakdown'},
        {type:'blocks',blocks:[
          {title:'Campaign Performance Matrix',dataType:'table',viewType:'table',cols:4,rows:2,desc:'Table of all active campaigns: Name, Platform, Spend, Revenue, ROAS, Impressions, CTR, Status (active/paused/ended)',color:'#14b8a6',
           sampleTable:{headers:['Campaign','Platform','Spend','Revenue','ROAS','CTR','Status'],rows:[['Spring Promo SP','Amazon','€142K','€681K','4.8x','0.82%','Active'],['Category Hero SB','Amazon','€98K','€412K','4.2x','0.41%','Active'],['Brand Awareness','Walmart','€76K','€296K','3.9x','0.63%','Active'],['Instacart Featured','Instacart','€54K','€281K','5.2x','1.12%','Active'],['Retargeting Q1','Criteo','€38K','€118K','3.1x','0.94%','Paused']]}}
        ]}
      ]}
    ]},
    {name:'Brand Health',pages:[
      {name:'Digital Shelf',rows:[
        {type:'blocks',blocks:[
          {title:'Search Share',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'Share of search in category across top 5 retailers',color:'#6366f1',sampleValue:'14.8%',sampleDelta:'+1.2pp'},
          {title:'Content Score',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'Average PDP content quality score (0-100)',color:'#22c55e',sampleValue:'87',sampleDelta:'+3pts'},
          {title:'Availability',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'In-stock rate across tracked SKUs',color:'#3b82f6',sampleValue:'96.2%',sampleDelta:'+0.8pp'},
          {title:'Avg Rating',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'Average product rating across retailers',color:'#f59e0b',sampleValue:'4.3★',sampleDelta:'+0.1'}
        ]},
        {type:'blocks',blocks:[
          {title:'Search Share Trend',dataType:'timeseries',viewType:'line',cols:2,rows:2,desc:'Weekly search share trend for our brand vs top 3 competitors in primary category',color:'#6366f1',
           sampleData:{labels:['W1','W2','W3','W4','W5','W6','W7','W8','W9','W10','W11','W12'],datasets:[{label:'Our Brand',data:[13.2,13.5,13.8,14.1,14.0,14.3,14.2,14.5,14.6,14.7,14.8,14.8],borderColor:'#6366f1',tension:0.3,borderWidth:3},{label:'Competitor A',data:[18.1,17.9,17.8,17.6,17.8,17.5,17.4,17.3,17.2,17.1,17.0,16.9],borderColor:'#ef4444',tension:0.3,borderWidth:2,borderDash:[5,5]},{label:'Competitor B',data:[11.2,11.3,11.1,11.4,11.5,11.3,11.6,11.5,11.7,11.8,11.6,11.9],borderColor:'#f59e0b',tension:0.3,borderWidth:2,borderDash:[5,5]}]}},
          {title:'Content Score by Retailer',dataType:'comparison',viewType:'radar',cols:2,rows:2,desc:'Content quality radar: Title, Images, Description, A+ Content, Ratings, Availability — per retailer',color:'#8b5cf6',
           sampleData:{labels:['Title','Images','Description','A+ Content','Ratings','Availability'],datasets:[{label:'Amazon',data:[92,88,85,90,87,97],borderColor:'#f59e0b',backgroundColor:'rgba(245,158,11,0.1)',pointBackgroundColor:'#f59e0b'},{label:'Walmart',data:[85,78,80,70,83,94],borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,0.1)',pointBackgroundColor:'#3b82f6'},{label:'Target',data:[80,82,75,65,81,91],borderColor:'#22c55e',backgroundColor:'rgba(34,197,94,0.1)',pointBackgroundColor:'#22c55e'}]}}
        ]}
      ]}
    ]}
  ];
  currentSetIdx=0;
  currentPageIdx=0;
}

/* ── Render ── */
function renderSetSelect(){
  var sel=document.getElementById('setSelect');
  sel.innerHTML=DATA.sets.map(function(s,i){return '<option value="'+i+'"'+(i===currentSetIdx?' selected':'')+'>'+esc(s.name)+'</option>'}).join('');
}
function switchSet(idx){currentSetIdx=+idx;currentPageIdx=0;renderPageTabs();renderCanvas();}
function renderPageTabs(){
  var wrap=document.getElementById('pageTabs');
  var set=DATA.sets[currentSetIdx];
  if(!set){wrap.innerHTML='';return;}
  wrap.innerHTML=set.pages.map(function(p,i){
    var active=i===currentPageIdx;
    return '<button onclick="switchPage('+i+')" class="px-3 py-1.5 text-xs font-semibold rounded-lg transition-all '+(active?'bg-violet-100 text-violet-700':'text-slate-500 hover:bg-slate-100')+'">'+esc(p.name)+'</button>';
  }).join('');
}
function switchPage(idx){currentPageIdx=idx;renderPageTabs();renderCanvas();}

function curPage(){
  var set=DATA.sets[currentSetIdx];
  if(!set)return null;
  return set.pages[currentPageIdx]||null;
}

function renderCanvas(){
  var page=curPage();
  var el=document.getElementById('canvas');
  if(!page){el.innerHTML='<div class="text-center py-20 text-slate-400">No pages. Click <b>+ Page</b> to start.</div>';return;}
  el.innerHTML='';
  page.rows.forEach(function(row,ri){
    var rowEl=document.createElement('div');
    rowEl.className='mb-4 fade-in';
    if(row.type==='text'){
      rowEl.innerHTML='<div class="flex items-center gap-2 group"><div contenteditable="true" class="flex-1 text-lg font-bold text-slate-700 px-4 py-3 rounded-xl hover:bg-white focus:bg-white focus:outline-none focus:ring-2 focus:ring-violet-300 transition" onblur="updateTextRow('+ri+',this.textContent)">'+esc(row.text||'Section Title')+'</div><button onclick="removeRow('+ri+')" class="opacity-0 group-hover:opacity-100 text-slate-300 hover:text-red-400 transition p-1">&#x2715;</button></div>';
    } else {
      var grid=document.createElement('div');
      grid.className='grid grid-cols-4 gap-4';
      grid.style.minHeight=UNIT_H+'px';
      (row.blocks||[]).forEach(function(b,bi){
        var card=document.createElement('div');
        card.className='block-card bg-white rounded-xl border border-slate-200 p-4 cursor-pointer overflow-hidden relative';
        card.style.gridColumn='span '+b.cols;
        card.style.minHeight=(UNIT_H*b.rows)+'px';
        card.onclick=function(){openBlockModal(ri,bi);};
        var accent=b.color||'#6366f1';
        var header='<div class="flex items-center justify-between mb-2"><div class="text-sm font-bold text-slate-800">'+esc(b.title||'Untitled')+'</div><div class="flex items-center gap-1"><span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-400">'+b.cols+'×'+b.rows+'</span></div></div>';
        header+='<div class="flex gap-1 mb-3"><span class="text-[10px] px-1.5 py-0.5 rounded font-medium" style="background:'+accent+'15;color:'+accent+'">'+esc(b.dataType||'')+'</span><span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-50 text-slate-400">'+esc(b.viewType||'')+'</span></div>';
        card.innerHTML=header;
        // Render preview
        renderBlockPreview(card,b);
        grid.appendChild(card);
      });
      // Add block button
      var addBtn=document.createElement('div');
      addBtn.className='block-ghost flex items-center justify-center cursor-pointer hover:border-violet-400 transition min-h-['+UNIT_H+'px]';
      addBtn.style.gridColumn='span 1';
      addBtn.style.minHeight=UNIT_H+'px';
      addBtn.innerHTML='<div class="text-center"><div class="text-2xl text-violet-300 mb-1">+</div><div class="text-xs text-violet-400 font-medium">Add Block</div></div>';
      addBtn.onclick=function(){addBlock(ri);};
      grid.appendChild(addBtn);

      var rowWrap=document.createElement('div');
      rowWrap.className='flex items-start gap-2 group';
      rowWrap.appendChild(grid);
      grid.style.flex='1';
      var rmBtn=document.createElement('button');
      rmBtn.className='opacity-0 group-hover:opacity-100 text-slate-300 hover:text-red-400 transition p-1 mt-2';
      rmBtn.innerHTML='&#x2715;';
      rmBtn.onclick=function(){removeRow(ri);};
      rowWrap.appendChild(rmBtn);
      rowEl.appendChild(rowWrap);
    }
    el.appendChild(rowEl);
  });
}

/* ── Block preview rendering ── */
function renderBlockPreview(container,block){
  var previewDiv=document.createElement('div');
  previewDiv.className='flex-1';
  previewDiv.style.minHeight=(UNIT_H*block.rows - 80)+'px';

  if(block.viewType==='number'){
    previewDiv.innerHTML='<div class="flex flex-col items-center justify-center h-full"><div class="text-3xl font-extrabold" style="color:'+(block.color||'#6366f1')+'">'+(block.sampleValue||'—')+'</div>'+(block.sampleDelta?'<div class="text-xs font-semibold mt-1 '+(block.sampleDelta.includes('-')?'text-red-500':'text-emerald-500')+'">'+esc(block.sampleDelta)+'</div>':'')+'</div>';
  } else if(block.viewType==='text'){
    previewDiv.innerHTML='<div class="text-sm text-slate-500 italic">'+esc(block.desc||'Text block')+'</div>';
  } else if(block.viewType==='table'&&block.sampleTable){
    var t='<table class="w-full text-[11px]"><thead><tr>'+block.sampleTable.headers.map(function(h){return '<th class="text-left py-1 px-2 text-slate-400 font-semibold border-b">'+esc(h)+'</th>'}).join('')+'</tr></thead><tbody>';
    block.sampleTable.rows.forEach(function(r,i){
      t+='<tr class="'+(i<3?'bg-violet-50/50':'')+'">'+r.map(function(c){return '<td class="py-1 px-2 text-slate-600 border-b border-slate-50">'+esc(c)+'</td>'}).join('')+'</tr>';
    });
    t+='</tbody></table>';
    previewDiv.innerHTML=t;
  } else if(block.sampleData){
    var canvas=document.createElement('canvas');
    canvas.style.width='100%';
    canvas.style.height=(UNIT_H*block.rows - 80)+'px';
    previewDiv.appendChild(canvas);
    setTimeout(function(){
      var type=block.viewType;
      if(type==='area')type='line';
      if(type==='horizontalBar')type='bar';
      var cfg={type:type,data:JSON.parse(JSON.stringify(block.sampleData)),options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:true,position:'bottom',labels:{boxWidth:8,font:{size:10,family:'Outfit'}}},tooltip:{enabled:true}},scales:{}}};
      if(type==='pie'||type==='doughnut'||type==='radar'||type==='polarArea'){delete cfg.options.scales;}
      else{cfg.options.scales={x:{grid:{display:false},ticks:{font:{size:10}}},y:{grid:{color:'rgba(0,0,0,0.04)'},ticks:{font:{size:10}}}};}
      if(block.viewType==='horizontalBar'){cfg.options.indexAxis='y';}
      if(block.viewType==='area'&&cfg.data.datasets){cfg.data.datasets.forEach(function(ds){ds.fill=true;});}
      try{new Chart(canvas,cfg);}catch(e){console.warn('Chart error',e);}
    },50);
  } else {
    previewDiv.innerHTML='<div class="flex items-center justify-center h-full text-slate-300 text-xs">Preview after data config</div>';
  }
  container.appendChild(previewDiv);
}

/* ── CRUD ── */
function addRow(){
  var page=curPage();if(!page)return;
  var type=prompt('Row type: "blocks" or "text"','blocks');
  if(!type)return;
  if(type==='text'){
    page.rows.push({type:'text',text:'New Section'});
  } else {
    page.rows.push({type:'blocks',blocks:[{title:'New Block',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'',color:COLORS[Math.floor(Math.random()*COLORS.length)],sampleValue:'0'}]});
  }
  renderCanvas();
}
function removeRow(ri){
  var page=curPage();if(!page)return;
  if(!confirm('Remove this row?'))return;
  page.rows.splice(ri,1);
  renderCanvas();
}
function updateTextRow(ri,text){
  var page=curPage();if(!page)return;
  page.rows[ri].text=text;
}
function addBlock(ri){
  var page=curPage();if(!page)return;
  var row=page.rows[ri];if(!row||row.type!=='blocks')return;
  row.blocks.push({title:'New Block',dataType:'kpi',viewType:'number',cols:1,rows:1,desc:'',color:COLORS[Math.floor(Math.random()*COLORS.length)],sampleValue:'0'});
  renderCanvas();
}

/* ── Block Modal ── */
function openBlockModal(ri,bi){
  editBlockRef={rowIdx:ri,blockIdx:bi};
  var page=curPage();
  var block=page.rows[ri].blocks[bi];
  document.getElementById('bm_title').value=block.title||'';
  document.getElementById('bm_dataType').value=block.dataType||'kpi';
  document.getElementById('bm_viewType').value=block.viewType||'number';
  document.getElementById('bm_cols').value=block.cols||1;
  document.getElementById('bm_rows').value=block.rows||1;
  document.getElementById('bm_desc').value=block.desc||'';
  // Color picker
  var colorEl=document.getElementById('bm_colors');
  colorEl.innerHTML=COLORS.map(function(c){
    var sel=(c===block.color)?'ring-2 ring-offset-2 ring-slate-400':'';
    return '<div onclick="pickColor(this,\''+c+'\')" class="w-7 h-7 rounded-full cursor-pointer hover:scale-110 transition '+sel+'" style="background:'+c+'"></div>';
  }).join('');
  document.getElementById('blockModal').classList.remove('hidden');
  document.getElementById('blockModal').classList.add('flex');
}
function closeBlockModal(){
  document.getElementById('blockModal').classList.add('hidden');
  document.getElementById('blockModal').classList.remove('flex');
  editBlockRef=null;
}
var _pickedColor=null;
function pickColor(el,c){
  _pickedColor=c;
  var all=el.parentNode.children;
  for(var i=0;i<all.length;i++){all[i].classList.remove('ring-2','ring-offset-2','ring-slate-400');}
  el.classList.add('ring-2','ring-offset-2','ring-slate-400');
}
function saveBlock(){
  if(!editBlockRef)return;
  var page=curPage();
  var block=page.rows[editBlockRef.rowIdx].blocks[editBlockRef.blockIdx];
  block.title=document.getElementById('bm_title').value;
  block.dataType=document.getElementById('bm_dataType').value;
  block.viewType=document.getElementById('bm_viewType').value;
  block.cols=+document.getElementById('bm_cols').value;
  block.rows=+document.getElementById('bm_rows').value;
  block.desc=document.getElementById('bm_desc').value;
  if(_pickedColor)block.color=_pickedColor;
  _pickedColor=null;
  closeBlockModal();
  renderCanvas();
}
function deleteBlock(){
  if(!editBlockRef)return;
  if(!confirm('Delete this block?'))return;
  var page=curPage();
  page.rows[editBlockRef.rowIdx].blocks.splice(editBlockRef.blockIdx,1);
  if(!page.rows[editBlockRef.rowIdx].blocks.length)page.rows.splice(editBlockRef.rowIdx,1);
  closeBlockModal();
  renderCanvas();
}

/* ── Sets & Pages ── */
function addSet(){
  var name=prompt('Dashboard set name:','New Set');
  if(!name)return;
  DATA.sets.push({name:name,pages:[{name:'Page 1',rows:[]}]});
  currentSetIdx=DATA.sets.length-1;
  currentPageIdx=0;
  renderSetSelect();renderPageTabs();renderCanvas();
}
function addPage(){
  var set=DATA.sets[currentSetIdx];if(!set)return;
  var name=prompt('Page name:','New Page');
  if(!name)return;
  set.pages.push({name:name,rows:[]});
  currentPageIdx=set.pages.length-1;
  renderPageTabs();renderCanvas();
}

/* ── Save ── */
function saveAll(){
  fetch('/api/analytics',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(DATA)})
    .then(function(r){return r.json()})
    .then(function(d){
      if(d.ok){showToast('Saved!');}else{showToast('Error saving','red');}
    });
}
function showToast(msg,color){
  var t=document.createElement('div');
  t.className='fixed bottom-6 right-6 px-5 py-3 rounded-xl text-white text-sm font-semibold shadow-2xl z-[999] fade-in';
  t.style.background=color||'#22c55e';
  t.textContent=msg;
  document.body.appendChild(t);
  setTimeout(function(){t.remove()},2500);
}

function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
</script>
</body></html>"""


# ──────────────────────────────────────────────
# CRON: Daily backup — /cron/daily-backup
# Copies blobs from 4 source buckets → gs://stratosx-backups-esj/YYYY-MM-DD/
# Protected by CRON_SECRET header (set in Cloud Scheduler)
# ──────────────────────────────────────────────
@app.route("/cron/daily-backup", methods=["POST"])
def cron_daily_backup():
    """Daily backup triggered by Cloud Scheduler."""
    # Verify CRON_SECRET (skip check if not configured — dev mode)
    incoming_secret = request.headers.get("X-Cron-Secret", "")
    if CRON_SECRET and incoming_secret != CRON_SECRET:
        log.warning("Backup rejected — bad CRON_SECRET from %s",
                    request.remote_addr)
        return jsonify({"error": "unauthorized"}), 403

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    client = _gcs()
    dest_bucket = client.bucket(BACKUP_DEST_BUCKET)
    stats = {"date": today, "buckets": {}}

    for src_name in BACKUP_SOURCE_BUCKETS:
        try:
            src_bucket = client.bucket(src_name)
            blobs = list(src_bucket.list_blobs())
            copied = 0
            for blob in blobs:
                dest_name = f"{today}/{src_name}/{blob.name}"
                src_bucket.copy_blob(blob, dest_bucket, dest_name)
                copied += 1
            stats["buckets"][src_name] = {
                "status": "ok",
                "blobs_copied": copied,
            }
            log.info("Backup %s: %d blobs → %s/%s/%s/",
                     src_name, copied, BACKUP_DEST_BUCKET,
                     today, src_name)
        except Exception as exc:
            stats["buckets"][src_name] = {
                "status": "error",
                "error": str(exc),
            }
            log.error("Backup %s failed: %s", src_name, exc)

    all_ok = all(
        b["status"] == "ok" for b in stats["buckets"].values()
    )
    stats["overall"] = "ok" if all_ok else "partial_failure"
    total = sum(
        b.get("blobs_copied", 0) for b in stats["buckets"].values()
    )
    log.info("Daily backup %s: %d blobs total, status=%s",
             today, total, stats["overall"])
    status_code = 200 if all_ok else 207
    return jsonify(stats), status_code


# ──────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=False)
