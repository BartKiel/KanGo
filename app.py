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
from datetime import datetime, timezone

from flask import (Flask, request, jsonify, make_response,
                   redirect, session)

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "kango-dev-key-change-me")

GCS_BUCKET = os.environ.get("GCS_BUCKET", "kango-tasks-esj")
PASSWORD_HASH = os.environ.get(
    "PASSWORD_HASH",
    hashlib.sha256("kango2026".encode()).hexdigest(),
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("kango")

DEFAULT_COLUMNS = [
    {"id": "auto-recommended",    "title": "\U0001f916 Auto-Recommended",      "color": "#6366f1"},
    {"id": "manually-recommended","title": "\U0001f4dd Manually Recommended",   "color": "#3b82f6"},
    {"id": "for-production",      "title": "\U0001f680 For Production",         "color": "#f59e0b"},
    {"id": "for-tests-confirm",   "title": "\U0001f9ea For Tests \u2014 Confirm","color": "#8b5cf6"},
    {"id": "delivered",           "title": "\U0001f4e6 Delivered",              "color": "#10b981"},
    {"id": "done",                "title": "\u2705 Done",                       "color": "#6b7280"},
]

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


def _migrate_columns(data):
    """Ensure the data has a 'columns' list; migrate from legacy bucket fields."""
    if "columns" not in data:
        data["columns"] = [dict(c) for c in DEFAULT_COLUMNS]
    return data


def load_tasks():
    try:
        bucket = _gcs().bucket(GCS_BUCKET)
        blob = bucket.blob("tasks.json")
        if blob.exists():
            data = json.loads(blob.download_as_text())
            return _migrate_columns(data)
    except Exception as exc:
        log.error("GCS read error: %s", exc)
    return {"tasks": [], "apps": list(DEFAULT_APPS), "columns": [dict(c) for c in DEFAULT_COLUMNS]}


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
        pw = request.form.get("password", "")
        if hashlib.sha256(pw.encode()).hexdigest() == PASSWORD_HASH:
            session["authed"] = True
            return redirect("/")
    error_div = '<div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-xl"><div class="flex items-center space-x-2"><svg class="w-4 h-4 text-red-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg><span class="text-sm text-red-600">Nieprawid\u0142owe has\u0142o</span></div></div>'

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
        "priority": body.get("priority", "medium"),
        "tags": body.get("tags", []),
        "app": body.get("app", ""),
        "app_directory": body.get("app_directory", ""),
        "bucket": body.get("bucket", "manually-recommended"),
        "estimated_time": body.get("estimated_time", ""),
        "comment": body.get("comment", ""),
        "source": body.get("source", "manual"),
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
            for key in ("title", "description", "priority", "tags", "app",
                        "app_directory", "bucket", "estimated_time", "comment",
                        "order", "source"):
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
# Column (list) API
# ──────────────────────────────────────────────
@app.route("/api/columns", methods=["GET"])
@login_required
def api_get_columns():
    data = load_tasks()
    return jsonify({"columns": data.get("columns", [])})


@app.route("/api/columns", methods=["POST"])
@login_required
def api_add_column():
    data = load_tasks()
    body = request.get_json(force=True)
    title = body.get("title", "").strip()
    if not title:
        return jsonify({"error": "title required"}), 400
    col = {
        "id": str(uuid.uuid4())[:12],
        "title": title,
        "color": body.get("color", "#64748b"),
    }
    data.setdefault("columns", []).append(col)
    save_tasks(data)
    return jsonify(col), 201


@app.route("/api/columns/<col_id>", methods=["PUT"])
@login_required
def api_update_column(col_id):
    data = load_tasks()
    body = request.get_json(force=True)
    for col in data.get("columns", []):
        if col["id"] == col_id:
            if "title" in body:
                col["title"] = body["title"].strip() or col["title"]
            if "color" in body:
                col["color"] = body["color"]
            save_tasks(data)
            return jsonify(col)
    return jsonify({"error": "not found"}), 404


@app.route("/api/columns/<col_id>", methods=["DELETE"])
@login_required
def api_delete_column(col_id):
    data = load_tasks()
    data["columns"] = [c for c in data.get("columns", []) if c["id"] != col_id]
    # Move orphaned tasks to the first remaining column (or delete them)
    remaining_ids = {c["id"] for c in data["columns"]}
    if remaining_ids:
        first_id = data["columns"][0]["id"]
        for t in data["tasks"]:
            if t.get("bucket") == col_id:
                t["bucket"] = first_id
    else:
        data["tasks"] = [t for t in data["tasks"] if t.get("bucket") != col_id]
    save_tasks(data)
    return jsonify({"ok": True})


@app.route("/api/columns/reorder", methods=["POST"])
@login_required
def api_reorder_columns():
    data = load_tasks()
    body = request.get_json(force=True)
    order = body.get("order", [])  # list of column ids in new order
    col_map = {c["id"]: c for c in data.get("columns", [])}
    reordered = [col_map[cid] for cid in order if cid in col_map]
    # Append any columns not in the order list (safety)
    seen = set(order)
    for c in data.get("columns", []):
        if c["id"] not in seen:
            reordered.append(c)
    data["columns"] = reordered
    save_tasks(data)
    return jsonify({"ok": True})


# ──────────────────────────────────────────────
# Board page  — plain string replacement, NO Jinja
# ──────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    log.info("Serving board page...")
    html = BOARD_PAGE
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    log.info("Board page served, %d bytes", len(html))
    return resp


# ══════════════════════════════════════════════
# HTML Templates (plain strings — no Jinja2)
# ══════════════════════════════════════════════

LOGIN_PAGE = r"""<!DOCTYPE html>
<html lang="pl"><head>
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
        <h2 class="text-2xl font-bold text-gray-900">Witaj ponownie</h2>
        <p class="text-sm text-gray-500 mt-1">Zaloguj si&#x119; do KanGo</p>
      </div>
      {{ERROR}}
      <form method="POST" class="space-y-5">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1.5">Has&#x142;o</label>
          <div class="relative">
            <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
              <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"/></svg>
            </span>
            <input type="password" name="password" autofocus required
              class="w-full pl-11 pr-4 py-3 text-sm border border-gray-300 rounded-xl bg-white text-gray-900 placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition"
              placeholder="Wprowad&#x17A; has&#x142;o...">
          </div>
        </div>
        <button type="submit"
          class="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-xl shadow-lg shadow-blue-500/25 transition-all duration-200 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
          Zaloguj si&#x119;
        </button>
      </form>
      <p class="text-center text-xs text-gray-400 mt-6">StratosX Ecosystem &bull; KanGo v1.0</p>
    </div>
  </div>
</div>
</body></html>"""


BOARD_PAGE = r"""<!DOCTYPE html>
<html lang="pl"><head>
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
.col-drag-over{opacity:.6;outline:2px dashed #3b82f6;outline-offset:2px}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.fade-card{animation:fadeIn .25s ease-out}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:10px}
::-webkit-scrollbar-thumb:hover{background:#94a3b8}
.col-title-input{background:transparent;border:none;outline:none;font-weight:600;font-size:.875rem;color:#334155;width:100%}
.col-title-input:focus{background:#f1f5f9;border-radius:.5rem;padding:0 .25rem}
</style></head>
<body class="bg-slate-50 font-outfit min-h-screen">

<!-- TOP BAR -->
<header class="bg-white border-b border-slate-200 sticky top-0 z-50">
  <div class="flex items-center justify-between px-6 h-16">
    <div class="flex items-center gap-3">
      <div class="w-9 h-9 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-xl flex items-center justify-center text-white text-lg shadow-lg shadow-blue-500/20">&#x1F4CB;</div>
      <div>
        <h1 class="text-lg font-bold text-slate-900 leading-none">KanGo</h1>
        <p class="text-[10px] text-slate-400 font-medium tracking-wide uppercase">StratosX Task Board</p>
      </div>
    </div>
    <div class="flex items-center gap-2">
      <button onclick="openModal()" class="inline-flex items-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-xl shadow-lg shadow-blue-500/20 transition-all">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>
        Nowy Task
      </button>
      <button onclick="openAppModal()" class="inline-flex items-center gap-1.5 px-3 py-2.5 text-slate-500 hover:text-slate-700 hover:bg-slate-50 text-sm font-medium rounded-xl border border-slate-200 transition-all">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 010 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 010-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28z"/><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
        Apps
      </button>
      <a href="/logout" class="inline-flex items-center gap-1.5 px-3 py-2.5 text-slate-400 hover:text-red-500 hover:bg-red-50 text-sm font-medium rounded-xl border border-slate-200 transition-all">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9"/></svg>
      </a>
    </div>
  </div>
  <!-- Stats bar -->
  <div class="px-6 pb-3 flex items-center gap-4" id="statsBar"></div>
</header>

<!-- BOARD -->
<div class="flex gap-5 p-6 min-h-[calc(100vh-7rem)] items-start overflow-x-auto" id="board"></div>

<!-- TASK MODAL -->
<div class="fixed inset-0 bg-black/40 backdrop-blur-sm z-[200] hidden items-center justify-center" id="taskModal">
<div class="bg-white rounded-2xl shadow-2xl w-[540px] max-w-[92vw] max-h-[88vh] overflow-y-auto p-8">
  <div class="flex items-center justify-between mb-6">
    <h2 id="mTitle" class="text-xl font-bold text-slate-900">Nowy Task</h2>
    <button onclick="closeModal()" class="w-8 h-8 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-400 hover:text-slate-600 transition">
      <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>
  </div>
  <input type="hidden" id="taskId">
  <div class="space-y-4">
    <div>
      <label class="block text-sm font-semibold text-slate-500 mb-1.5">Tytu&#x142;</label>
      <input id="fTitle" placeholder="Kr&oacute;tki tytu&#x142;..." class="w-full px-4 py-2.5 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition">
    </div>
    <div>
      <label class="block text-sm font-semibold text-slate-500 mb-1.5">Opis</label>
      <textarea id="fDesc" rows="3" placeholder="Co trzeba zrobi&#x107;..." class="w-full px-4 py-2.5 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition resize-y"></textarea>
    </div>
    <div class="grid grid-cols-2 gap-4">
      <div>
        <label class="block text-sm font-semibold text-slate-500 mb-1.5">Priorytet</label>
        <select id="fPriority" class="w-full px-4 py-2.5 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">
          <option value="low">&#x1F7E2; Low</option><option value="medium" selected>&#x1F7E1; Medium</option><option value="high">&#x1F7E0; High</option><option value="critical">&#x1F534; Critical</option>
        </select>
      </div>
      <div>
        <label class="block text-sm font-semibold text-slate-500 mb-1.5">Lista</label>
        <select id="fBucket" class="w-full px-4 py-2.5 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition"></select>
      </div>
    </div>
    <div class="grid grid-cols-2 gap-4">
      <div>
        <label class="block text-sm font-semibold text-slate-500 mb-1.5">Aplikacja</label>
        <select id="fApp" class="w-full px-4 py-2.5 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition"><option value="">&#x2014; brak &#x2014;</option></select>
      </div>
      <div>
        <label class="block text-sm font-semibold text-slate-500 mb-1.5">Szacowany czas</label>
        <input id="fTime" placeholder="np. 2h, 30min" class="w-full px-4 py-2.5 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">
      </div>
    </div>
    <div>
      <label class="block text-sm font-semibold text-slate-500 mb-1.5">Katalog aplikacji</label>
      <input id="fDir" placeholder="~/Documents/Coding_space-Python/..." class="w-full px-4 py-2.5 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition font-mono text-xs">
    </div>
    <div>
      <label class="block text-sm font-semibold text-slate-500 mb-1.5">Tagi (przecinkiem)</label>
      <input id="fTags" placeholder="refactor, security, ui" class="w-full px-4 py-2.5 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">
    </div>
    <div>
      <label class="block text-sm font-semibold text-slate-500 mb-1.5">Komentarz</label>
      <textarea id="fComment" rows="2" placeholder="Notatki..." class="w-full px-4 py-2.5 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition resize-y"></textarea>
    </div>
  </div>
  <div class="flex gap-3 justify-end mt-6 pt-4 border-t border-slate-100">
    <button class="px-4 py-2.5 text-sm font-medium text-slate-500 hover:bg-slate-50 rounded-xl border border-slate-200 transition" onclick="closeModal()">Anuluj</button>
    <button class="px-6 py-2.5 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl shadow-lg shadow-blue-500/20 transition" onclick="saveTask()">Zapisz</button>
  </div>
</div></div>

<!-- APP MODAL -->
<div class="fixed inset-0 bg-black/40 backdrop-blur-sm z-[200] hidden items-center justify-center" id="appModal">
<div class="bg-white rounded-2xl shadow-2xl w-[440px] max-w-[92vw] max-h-[80vh] overflow-y-auto p-8">
  <div class="flex items-center justify-between mb-6">
    <h2 class="text-xl font-bold text-slate-900">Aplikacje</h2>
    <button onclick="closeAppModal()" class="w-8 h-8 rounded-lg hover:bg-slate-100 flex items-center justify-center text-slate-400 hover:text-slate-600 transition">
      <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>
  </div>
  <div class="flex gap-2 mb-4">
    <input id="newAppName" placeholder="Nowa aplikacja..." class="flex-1 px-4 py-2.5 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition">
    <button onclick="addApp()" class="px-4 py-2.5 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition">Dodaj</button>
  </div>
  <div id="appList" class="space-y-1"></div>
</div></div>

<script>
var S={tasks:[],apps:[],columns:[]};

var PRIO_CFG={
  critical:{label:'Critical',icon:'\ud83d\udd34',bg:'bg-red-50',text:'text-red-600',border:'border-red-100',ring:'ring-red-500/20'},
  high:{label:'High',icon:'\ud83d\udfe0',bg:'bg-amber-50',text:'text-amber-600',border:'border-amber-100',ring:'ring-amber-500/20'},
  medium:{label:'Medium',icon:'\ud83d\udfe1',bg:'bg-yellow-50',text:'text-yellow-600',border:'border-yellow-100',ring:'ring-yellow-500/20'},
  low:{label:'Low',icon:'\ud83d\udfe2',bg:'bg-emerald-50',text:'text-emerald-600',border:'border-emerald-100',ring:'ring-emerald-500/20'}
};

var PALETTE=['#6366f1','#3b82f6','#f59e0b','#8b5cf6','#10b981','#ef4444','#ec4899','#14b8a6','#f97316','#6b7280'];

function load(){
  fetch('/api/tasks').then(function(r){return r.json()}).then(function(d){
    S.tasks=d.tasks||[];S.apps=d.apps||[];
    S.columns=d.columns||[];
    render();
  }).catch(function(e){console.error(e);render()});
}

function render(){
  var b=document.getElementById('board');b.innerHTML='';
  var allTasks=S.tasks||[];
  var total=allTasks.length;
  var doneCols=(S.columns||[]).filter(function(c){return c.id==='done'}).map(function(c){return c.id});
  var doneCnt=allTasks.filter(function(t){return doneCols.indexOf(t.bucket)>=0}).length;
  var critCnt=allTasks.filter(function(t){return t.priority==='critical'&&doneCols.indexOf(t.bucket)<0}).length;
  var bar=document.getElementById('statsBar');
  bar.innerHTML='<div class="flex items-center gap-1.5 text-xs font-medium text-slate-400"><span class="w-2 h-2 rounded-full bg-slate-300"></span>'+total+' tasks</div>'
    +'<div class="flex items-center gap-1.5 text-xs font-medium text-emerald-500"><span class="w-2 h-2 rounded-full bg-emerald-400"></span>'+doneCnt+' done</div>'
    +(critCnt?'<div class="flex items-center gap-1.5 text-xs font-medium text-red-500"><span class="w-2 h-2 rounded-full bg-red-400 animate-pulse"></span>'+critCnt+' critical</div>':'');

  (S.columns||[]).forEach(function(col,colIdx){
    var bk=col.id;
    var tasks=allTasks.filter(function(t){return t.bucket===bk}).sort(function(ta,tb){return(ta.order||999)-(tb.order||999)});
    var colEl=document.createElement('div');
    colEl.className='min-w-[290px] max-w-[320px] flex-1 flex flex-col rounded-2xl border border-slate-200 bg-white shadow-sm max-h-[calc(100vh-8rem)]';
    colEl.draggable=true;
    colEl.setAttribute('data-col-id',bk);

    // Column drag (reorder columns)
    colEl.addEventListener('dragstart',function(e){
      if(e.target!==colEl&&!e.target.closest('.col-drag-handle'))return;
      e.dataTransfer.setData('col-drag',bk);
      e.dataTransfer.effectAllowed='move';
    });
    colEl.addEventListener('dragover',function(e){
      if(e.dataTransfer.types.indexOf('col-drag')>=0){e.preventDefault();colEl.classList.add('col-drag-over')}
    });
    colEl.addEventListener('dragleave',function(){colEl.classList.remove('col-drag-over')});
    colEl.addEventListener('drop',function(e){
      colEl.classList.remove('col-drag-over');
      var srcId=e.dataTransfer.getData('col-drag');
      if(srcId&&srcId!==bk){reorderColumns(srcId,bk)}
      else if(!srcId){
        e.preventDefault();
        var cardId=e.dataTransfer.getData('text/plain');
        if(cardId)onDrop(e,bk);
      }
    });

    var color=col.color||'#64748b';
    var hd=document.createElement('div');
    hd.className='px-3 py-3.5 border-b border-slate-100 flex items-center gap-2 col-drag-handle cursor-grab';
    hd.innerHTML='<span class="w-2.5 h-2.5 rounded-full flex-shrink-0 shadow-sm" style="background:'+color+'"></span>'
      +'<input class="col-title-input flex-1 min-w-0" value="'+esc(col.title)+'" title="Kliknij aby edytowa\u0107 nazw\u0119 listy" data-col-id="'+bk+'">'
      +'<span class="text-xs font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 flex-shrink-0">'+tasks.length+'</span>'
      +'<button onclick="delColumn(\''+bk+'\')" class="w-6 h-6 rounded-lg hover:bg-red-50 hover:text-red-500 flex items-center justify-center text-slate-300 transition flex-shrink-0" title="Usu\u0144 list\u0119">'
      +'<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg></button>';

    // Inline rename on Enter/blur
    var inp=hd.querySelector('input.col-title-input');
    inp.addEventListener('keydown',function(e){if(e.key==='Enter'){inp.blur()}});
    inp.addEventListener('blur',function(){
      var newTitle=inp.value.trim();
      if(newTitle&&newTitle!==col.title){renameColumn(bk,newTitle)}
    });
    // Prevent column drag when clicking input
    inp.addEventListener('mousedown',function(e){e.stopPropagation()});

    colEl.appendChild(hd);

    var body=document.createElement('div');
    body.className='p-2.5 flex-1 overflow-y-auto space-y-2 min-h-[60px] rounded-b-2xl transition-colors duration-200';
    body.setAttribute('data-bucket',bk);
    body.addEventListener('dragover',function(e){
      if(e.dataTransfer.types.indexOf('col-drag')<0){e.preventDefault();body.classList.add('drag-over')}
    });
    body.addEventListener('dragleave',function(){body.classList.remove('drag-over')});
    body.addEventListener('drop',function(e){
      body.classList.remove('drag-over');
      if(e.dataTransfer.types.indexOf('col-drag')>=0)return;
      e.preventDefault();onDrop(e,bk);
    });

    // "Add card" button at bottom
    var addCardBtn=document.createElement('button');
    addCardBtn.className='w-full mt-1 py-2 text-xs font-medium text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-xl flex items-center justify-center gap-1 transition';
    addCardBtn.innerHTML='<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>Dodaj kart\u0119';
    addCardBtn.onclick=function(){openModal(null,bk)};

    if(!tasks.length){
      body.innerHTML='<div class="text-center py-8 text-slate-300 text-xs font-medium">Przeci\u0105gnij tutaj...</div>';
    } else {
      tasks.forEach(function(t){body.appendChild(mkCard(t))});
    }
    body.appendChild(addCardBtn);
    colEl.appendChild(body);
    b.appendChild(colEl);
  });

  // "Add list" button
  var addCol=document.createElement('div');
  addCol.className='min-w-[230px] flex-shrink-0 flex flex-col';
  addCol.innerHTML='<div id="addColForm" class="rounded-2xl border border-dashed border-slate-300 bg-white/60 p-3">'
    +'<div id="addColPrompt" class="flex items-center gap-2 cursor-pointer text-slate-400 hover:text-blue-600 transition px-1" onclick="showAddColForm()">'
    +'<svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>'
    +'<span class="text-sm font-medium">Dodaj list\u0119</span></div>'
    +'<div id="addColInput" class="hidden space-y-2">'
    +'<input id="newColTitle" placeholder="Nazwa listy..." class="w-full px-3 py-2 text-sm border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none">'
    +'<div class="flex gap-2">'
    +'<button onclick="addColumn()" class="flex-1 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition">Dodaj list\u0119</button>'
    +'<button onclick="hideAddColForm()" class="py-2 px-3 text-xs text-slate-400 hover:bg-slate-100 rounded-xl transition">&times;</button>'
    +'</div></div></div>';
  b.appendChild(addCol);

  updAppSel();
  updBucketSel();
}

function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}

function mkCard(t){
  var c=document.createElement('div');
  c.className='group relative p-3.5 rounded-xl border border-slate-150 bg-white hover:shadow-md hover:border-slate-200 cursor-grab transition-all duration-150 fade-card';
  c.draggable=true;c.setAttribute('data-id',t.id);
  c.addEventListener('dragstart',function(e){e.dataTransfer.setData('text/plain',t.id);c.classList.add('card-drag')});
  c.addEventListener('dragend',function(){c.classList.remove('card-drag')});

  var p=PRIO_CFG[t.priority]||PRIO_CFG.medium;
  var h='<div class="absolute top-2.5 right-2.5 hidden group-hover:flex gap-1">';
  h+='<button onclick="editTask(\''+t.id+'\')" class="w-7 h-7 rounded-lg bg-slate-50 hover:bg-blue-50 hover:text-blue-600 flex items-center justify-center text-slate-400 transition text-xs" title="Edytuj"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z"/></svg></button>';
  h+='<button onclick="delTask(\''+t.id+'\')" class="w-7 h-7 rounded-lg bg-slate-50 hover:bg-red-50 hover:text-red-500 flex items-center justify-center text-slate-400 transition text-xs" title="Usu\u0144"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/></svg></button>';
  h+='</div>';

  h+='<div class="text-[13px] font-semibold text-slate-800 leading-snug pr-14 mb-1.5">'+esc(t.title||'Untitled')+'</div>';
  if(t.description) h+='<div class="text-xs text-slate-400 leading-relaxed mb-2.5 line-clamp-2">'+esc(t.description)+'</div>';

  var tags='';
  (t.tags||[]).forEach(function(g){tags+='<span class="text-[10px] font-medium px-2 py-0.5 rounded-md bg-slate-100 text-slate-500">'+esc(g)+'</span>'});
  if(t.app) tags+='<span class="text-[10px] font-medium px-2 py-0.5 rounded-md bg-blue-50 text-blue-600">'+esc(t.app)+'</span>';
  if(tags) h+='<div class="flex flex-wrap gap-1 mb-2.5">'+tags+'</div>';

  h+='<div class="flex items-center justify-between">';
  h+='<span class="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-md ring-1 '+p.ring+' '+p.bg+' '+p.text+'">'+p.icon+' '+p.label+'</span>';
  var right='';
  if(t.estimated_time) right+='<span class="text-[10px] font-medium text-violet-500">\u23f1 '+esc(t.estimated_time)+'</span>';
  right+='<span class="text-[10px] opacity-50">'+(t.source==='copilot'?'\ud83e\udd16':'\ud83d\udc64')+'</span>';
  h+='<div class="flex items-center gap-2">'+right+'</div></div>';

  if(t.app_directory) h+='<div class="mt-2 text-[10px] font-mono text-slate-400 bg-slate-50 px-2 py-1 rounded-lg truncate">\ud83d\udcc1 '+esc(t.app_directory)+'</div>';
  if(t.comment) h+='<div class="mt-2 text-[11px] text-emerald-600 font-medium leading-relaxed bg-emerald-50 px-2.5 py-1.5 rounded-lg">\ud83d\udcac '+esc(t.comment)+'</div>';

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

// ── Column management ──
function showAddColForm(){
  document.getElementById('addColPrompt').classList.add('hidden');
  document.getElementById('addColInput').classList.remove('hidden');
  document.getElementById('newColTitle').focus();
}
function hideAddColForm(){
  document.getElementById('addColPrompt').classList.remove('hidden');
  document.getElementById('addColInput').classList.add('hidden');
  document.getElementById('newColTitle').value='';
}
function addColumn(){
  var title=document.getElementById('newColTitle').value.trim();
  if(!title)return;
  var color=PALETTE[S.columns.length%PALETTE.length];
  fetch('/api/columns',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:title,color:color})})
    .then(function(r){return r.json()}).then(function(){load()});
}
function renameColumn(colId,newTitle){
  fetch('/api/columns/'+colId,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:newTitle})})
    .then(function(){load()});
}
function delColumn(colId){
  var col=S.columns.find(function(c){return c.id===colId});
  var taskCount=S.tasks.filter(function(t){return t.bucket===colId}).length;
  var msg='Usun\u0105\u0107 list\u0119'+(col?' "'+col.title+'"':'')+' ?';
  if(taskCount>0)msg+='\n\nListy zawiera '+taskCount+' kart(y) \u2014 zostan\u0105 przeniesione do pierwszej dost\u0119pnej listy.';
  if(!confirm(msg))return;
  fetch('/api/columns/'+colId,{method:'DELETE'}).then(load);
}
function reorderColumns(srcId,targetId){
  var cols=S.columns.slice();
  var si=cols.findIndex(function(c){return c.id===srcId});
  var ti=cols.findIndex(function(c){return c.id===targetId});
  if(si<0||ti<0)return;
  var moved=cols.splice(si,1)[0];
  cols.splice(ti,0,moved);
  S.columns=cols;
  render();
  fetch('/api/columns/reorder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({order:cols.map(function(c){return c.id})})});
}

// ── Task modal ──
function openModal(id,defaultBucket){
  var m=document.getElementById('taskModal');m.classList.remove('hidden');m.classList.add('flex');
  updBucketSel();
  if(id){
    var t=S.tasks.find(function(x){return x.id===id});if(!t)return;
    document.getElementById('mTitle').textContent='Edytuj Task';
    document.getElementById('taskId').value=t.id;
    document.getElementById('fTitle').value=t.title||'';
    document.getElementById('fDesc').value=t.description||'';
    document.getElementById('fPriority').value=t.priority||'medium';
    document.getElementById('fBucket').value=t.bucket||(S.columns[0]&&S.columns[0].id)||'';
    document.getElementById('fApp').value=t.app||'';
    document.getElementById('fTime').value=t.estimated_time||'';
    document.getElementById('fDir').value=t.app_directory||'';
    document.getElementById('fTags').value=(t.tags||[]).join(', ');
    document.getElementById('fComment').value=t.comment||'';
  }else{
    document.getElementById('mTitle').textContent='Nowy Task';
    ['taskId','fTitle','fDesc','fTime','fDir','fTags','fComment'].forEach(function(x){document.getElementById(x).value=''});
    document.getElementById('fPriority').value='medium';
    document.getElementById('fBucket').value=defaultBucket||(S.columns[0]&&S.columns[0].id)||'';
    document.getElementById('fApp').value='';
  }
}
function closeModal(){var m=document.getElementById('taskModal');m.classList.add('hidden');m.classList.remove('flex')}
function editTask(id){openModal(id)}
function delTask(id){if(!confirm('Usun\u0105\u0107 ten task?'))return;fetch('/api/tasks/'+id,{method:'DELETE'}).then(load)}
function saveTask(){
  var id=document.getElementById('taskId').value;
  var body={title:document.getElementById('fTitle').value,description:document.getElementById('fDesc').value,priority:document.getElementById('fPriority').value,bucket:document.getElementById('fBucket').value,app:document.getElementById('fApp').value,estimated_time:document.getElementById('fTime').value,app_directory:document.getElementById('fDir').value,tags:document.getElementById('fTags').value.split(',').map(function(s){return s.trim()}).filter(Boolean),comment:document.getElementById('fComment').value,source:'manual'};
  var url=id?'/api/tasks/'+id:'/api/tasks';
  var method=id?'PUT':'POST';
  fetch(url,{method:method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(){closeModal();load()});
}
function updBucketSel(){
  var s=document.getElementById('fBucket');if(!s)return;
  var v=s.value;
  s.innerHTML='';
  (S.columns||[]).forEach(function(col){var o=document.createElement('option');o.value=col.id;o.textContent=col.title;if(col.id===v)o.selected=true;s.appendChild(o)});
}
function updAppSel(){
  var s=document.getElementById('fApp');var v=s.value;
  s.innerHTML='<option value="">\u2014 brak \u2014</option>';
  (S.apps||[]).forEach(function(a){var o=document.createElement('option');o.value=a;o.textContent=a;if(a===v)o.selected=true;s.appendChild(o)});
}
function openAppModal(){var m=document.getElementById('appModal');m.classList.remove('hidden');m.classList.add('flex');renderApps()}
function closeAppModal(){var m=document.getElementById('appModal');m.classList.add('hidden');m.classList.remove('flex')}
function renderApps(){document.getElementById('appList').innerHTML=(S.apps||[]).map(function(a){return'<div class="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-slate-50 text-sm text-slate-700"><span class="w-2 h-2 rounded-full bg-blue-400"></span>'+esc(a)+'</div>'}).join('')}
function addApp(){var i=document.getElementById('newAppName');var n=i.value.trim();if(!n)return;fetch('/api/apps',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})}).then(function(){i.value='';load();renderApps()})}

// Close modals on backdrop click
document.getElementById('taskModal').addEventListener('click',function(e){if(e.target===this)closeModal()});
document.getElementById('appModal').addEventListener('click',function(e){if(e.target===this)closeAppModal()});
// ESC key
document.addEventListener('keydown',function(e){
  if(e.key==='Escape'){closeModal();closeAppModal();hideAddColForm();}
  if(e.key==='Enter'){var ac=document.getElementById('addColInput');if(ac&&!ac.classList.contains('hidden')){addColumn();}}
});

load();
</script></body></html>"""


# ──────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
