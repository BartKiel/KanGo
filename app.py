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
        pw = request.form.get("password", "")
        if hashlib.sha256(pw.encode()).hexdigest() == PASSWORD_HASH:
            session["authed"] = True
            return redirect("/")
        error_div = '<div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-xl"><div class="flex items-center space-x-2"><svg class="w-4 h-4 text-red-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg><span class="text-sm text-red-600">Incorrect password</span></div></div>'

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
          <label class="block text-sm font-medium text-gray-700 mb-1.5">Password</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
              <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"/></svg>
            </span>
            <input type="password" name="password" autofocus required
              class="w-full pl-11 pr-4 py-3 text-sm border border-gray-300 rounded-xl bg-white text-gray-900 placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition"
              placeholder="Enter password...">
          </div>
        </div>
        <button type="submit"
          class="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-xl shadow-lg shadow-blue-500/25 transition-all duration-200 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
          Sign In
        </button>
      </form>
      <p class="text-center text-xs text-gray-400 mt-6">StratosX Ecosystem &bull; KanGo v1.0</p>
    </div>
  </div>
</div>
</body></html>"""


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
      <button onclick="toggleFilesPanel()" class="inline-flex items-center gap-1.5 px-3 py-2.5 text-slate-500 hover:text-slate-700 hover:bg-slate-50 text-sm font-medium rounded-xl border border-slate-200 transition-all">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z"/></svg>
        Files
      </button>
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


# ──────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=False)
