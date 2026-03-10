"""
KanGo — Lightweight Kanban Task Board
Cloud Run + GCS JSON backend
"""

import os
import json
import uuid
import hashlib
import functools
from datetime import datetime, timezone

from flask import Flask, request, jsonify, render_template_string, redirect, session, abort
from google.cloud import storage

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "kango-dev-key-change-me")

GCS_BUCKET = os.environ.get("GCS_BUCKET", "kango-tasks-esj")
PASSWORD_HASH = os.environ.get(
    "PASSWORD_HASH",
    # default: sha256 of "kango2026" — change via env var
    hashlib.sha256("kango2026".encode()).hexdigest(),
)

BUCKETS_ORDER = [
    "auto-recommended",
    "manually-recommended",
    "for-production",
    "for-tests-confirm",
    "delivered",
    "done",
]

BUCKET_LABELS = {
    "auto-recommended": "🤖 Auto-Recommended",
    "manually-recommended": "📝 Manually Recommended",
    "for-production": "🚀 For Production",
    "for-tests-confirm": "🧪 For Tests — Confirm",
    "delivered": "📦 Delivered",
    "done": "✅ Done",
}

BUCKET_COLORS = {
    "auto-recommended": "#6366f1",
    "manually-recommended": "#3b82f6",
    "for-production": "#f59e0b",
    "for-tests-confirm": "#8b5cf6",
    "delivered": "#10b981",
    "done": "#6b7280",
}

# ──────────────────────────────────────────────
# GCS helpers
# ──────────────────────────────────────────────
_client = None


def gcs():
    global _client
    if _client is None:
        _client = storage.Client()
    return _client


def load_tasks():
    """Load tasks.json from GCS."""
    try:
        bucket = gcs().bucket(GCS_BUCKET)
        blob = bucket.blob("tasks.json")
        if blob.exists():
            return json.loads(blob.download_as_text())
    except Exception as e:
        print(f"GCS read error: {e}")
    return {"tasks": [], "apps": ["StratosX", "GeoCatch", "CriteriaBuilder", "MindCloud", "OralB Dashboard", "PDPCatch", "StratosX Brand", "KanGo"]}


def save_tasks(data):
    """Save tasks.json to GCS."""
    try:
        bucket = gcs().bucket(GCS_BUCKET)
        blob = bucket.blob("tasks.json")
        blob.upload_from_string(
            json.dumps(data, ensure_ascii=False, indent=2),
            content_type="application/json",
        )
        return True
    except Exception as e:
        print(f"GCS write error: {e}")
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
    error = ""
    if request.method == "POST":
        pw = request.form.get("password", "")
        if hashlib.sha256(pw.encode()).hexdigest() == PASSWORD_HASH:
            session["authed"] = True
            return redirect("/")
        error = "Nieprawidłowe hasło"
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ──────────────────────────────────────────────
# API — Tasks CRUD
# ──────────────────────────────────────────────
@app.route("/api/tasks", methods=["GET"])
@login_required
def api_get_tasks():
    data = load_tasks()
    return jsonify(data)


@app.route("/api/tasks", methods=["POST"])
@login_required
def api_create_task():
    data = load_tasks()
    body = request.get_json(force=True)

    task = {
        "id": str(uuid.uuid4())[:12],
        "title": body.get("title", "Untitled"),
        "description": body.get("description", ""),
        "priority": body.get("priority", "medium"),  # low, medium, high, critical
        "tags": body.get("tags", []),
        "app": body.get("app", ""),
        "app_directory": body.get("app_directory", ""),
        "bucket": body.get("bucket", "manually-recommended"),
        "estimated_time": body.get("estimated_time", ""),
        "comment": body.get("comment", ""),
        "source": body.get("source", "manual"),  # manual | copilot
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
            for key in ["title", "description", "priority", "tags", "app",
                        "app_directory", "bucket", "estimated_time", "comment",
                        "order", "source"]:
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
    """Batch update bucket + order for drag & drop."""
    data = load_tasks()
    body = request.get_json(force=True)
    updates = body.get("updates", [])  # [{id, bucket, order}, ...]

    task_map = {t["id"]: t for t in data["tasks"]}
    for u in updates:
        if u["id"] in task_map:
            task_map[u["id"]]["bucket"] = u["bucket"]
            task_map[u["id"]]["order"] = u["order"]
            task_map[u["id"]]["updated_at"] = datetime.now(timezone.utc).isoformat()

    save_tasks(data)
    return jsonify({"ok": True})


@app.route("/api/apps", methods=["POST"])
@login_required
def api_add_app():
    data = load_tasks()
    body = request.get_json(force=True)
    app_name = body.get("name", "").strip()
    if app_name and app_name not in data.get("apps", []):
        data.setdefault("apps", []).append(app_name)
        save_tasks(data)
    return jsonify({"apps": data.get("apps", [])})


# ──────────────────────────────────────────────
# Main page
# ──────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    return render_template_string(BOARD_HTML,
                                  buckets_order=BUCKETS_ORDER,
                                  bucket_labels=BUCKET_LABELS,
                                  bucket_colors=BUCKET_COLORS)


# ──────────────────────────────────────────────
# Templates
# ──────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KanGo — Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif;background:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh}
.login{background:#fff;border-radius:16px;padding:48px;width:380px;box-shadow:0 4px 24px rgba(0,0,0,0.08)}
.login h1{font-size:28px;font-weight:700;color:#1e293b;margin-bottom:8px;text-align:center}
.login p{color:#64748b;text-align:center;margin-bottom:32px;font-size:14px}
.login input{width:100%;padding:12px 16px;border:1px solid #e2e8f0;border-radius:8px;font-size:15px;margin-bottom:16px;outline:none;transition:border .2s}
.login input:focus{border-color:#3b82f6}
.login button{width:100%;padding:12px;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
.login button:hover{background:#2563eb}
.error{color:#ef4444;font-size:13px;text-align:center;margin-bottom:12px}
.logo{font-size:40px;text-align:center;margin-bottom:16px}
</style></head><body>
<form class="login" method="POST">
<div class="logo">📋</div>
<h1>KanGo</h1>
<p>Lightweight Kanban for StratosX</p>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<input type="password" name="password" placeholder="Hasło..." autofocus>
<button type="submit">Zaloguj się</button>
</form></body></html>"""


BOARD_HTML = r"""<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KanGo — Task Board</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f1f5f9;--card:#fff;--border:#e2e8f0;--text:#1e293b;--dim:#64748b;--blue:#3b82f6;
  --green:#10b981;--amber:#f59e0b;--red:#ef4444;--purple:#8b5cf6;--indigo:#6366f1;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);overflow-x:auto}

/* TOP BAR */
.topbar{background:#fff;border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.topbar h1{font-size:20px;font-weight:700;display:flex;align-items:center;gap:8px}
.topbar-actions{display:flex;gap:8px;align-items:center}
.btn{padding:8px 16px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:none;transition:all .2s;display:flex;align-items:center;gap:6px}
.btn-primary{background:var(--blue);color:#fff}
.btn-primary:hover{background:#2563eb}
.btn-ghost{background:transparent;color:var(--dim);border:1px solid var(--border)}
.btn-ghost:hover{background:#f8fafc}

/* BOARD */
.board{display:flex;gap:16px;padding:20px 24px;min-height:calc(100vh - 60px);align-items:flex-start;overflow-x:auto}
.column{min-width:300px;max-width:340px;flex:1;background:#fff;border-radius:12px;border:1px solid var(--border);display:flex;flex-direction:column;max-height:calc(100vh - 100px)}
.column-header{padding:16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0}
.column-title{font-size:14px;font-weight:600;display:flex;align-items:center;gap:8px}
.column-count{background:#f1f5f9;color:var(--dim);font-size:12px;font-weight:600;padding:2px 8px;border-radius:10px}
.column-dot{width:10px;height:10px;border-radius:50%}
.column-body{padding:8px;flex:1;overflow-y:auto;min-height:60px}
.column-body.drag-over{background:#eff6ff;border-radius:0 0 12px 12px}

/* CARDS */
.task-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:8px;cursor:grab;transition:all .15s;position:relative}
.task-card:hover{box-shadow:0 2px 8px rgba(0,0,0,0.06);border-color:#cbd5e1}
.task-card:active{cursor:grabbing;opacity:0.8;transform:rotate(1deg)}
.task-card.dragging{opacity:0.4;transform:scale(0.95)}
.task-title{font-size:14px;font-weight:600;margin-bottom:6px;line-height:1.3}
.task-desc{font-size:12px;color:var(--dim);margin-bottom:8px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.task-meta{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px}
.task-tag{font-size:11px;padding:2px 8px;border-radius:6px;background:#f1f5f9;color:var(--dim);font-weight:500}
.task-app{font-size:11px;padding:2px 8px;border-radius:6px;background:#eff6ff;color:var(--blue);font-weight:500}
.task-footer{display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--dim)}
.task-priority{font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px}
.priority-critical{background:#fef2f2;color:var(--red)}
.priority-high{background:#fff7ed;color:#ea580c}
.priority-medium{background:#fefce8;color:#ca8a04}
.priority-low{background:#f0fdf4;color:var(--green)}
.task-source{font-size:10px;opacity:0.6}
.task-time{font-size:11px;color:var(--purple);font-weight:500}
.task-comment{font-size:11px;color:var(--green);margin-top:4px;font-style:italic}
.task-dir{font-size:10px;color:var(--dim);font-family:monospace;margin-top:4px;background:#f8fafc;padding:2px 6px;border-radius:4px;display:inline-block}
.task-actions{position:absolute;top:8px;right:8px;display:none;gap:4px}
.task-card:hover .task-actions{display:flex}
.task-action-btn{width:24px;height:24px;border-radius:6px;border:none;background:#f1f5f9;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;transition:background .15s}
.task-action-btn:hover{background:#e2e8f0}

/* MODAL */
.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.4);z-index:200;display:none;align-items:center;justify-content:center}
.modal-overlay.active{display:flex}
.modal{background:#fff;border-radius:16px;padding:32px;width:520px;max-width:90vw;max-height:85vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,0.15)}
.modal h2{font-size:20px;font-weight:700;margin-bottom:20px}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:13px;font-weight:600;color:var(--dim);margin-bottom:6px}
.form-group input,.form-group textarea,.form-group select{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:8px;font-size:14px;font-family:inherit;outline:none;transition:border .2s}
.form-group input:focus,.form-group textarea:focus,.form-group select:focus{border-color:var(--blue)}
.form-group textarea{resize:vertical;min-height:60px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:24px}

/* PLACEHOLDER for empty columns */
.empty-placeholder{text-align:center;padding:24px;color:#cbd5e1;font-size:13px}
</style></head>
<body>

<!-- TOP BAR -->
<div class="topbar">
  <h1>📋 KanGo</h1>
  <div class="topbar-actions">
    <button class="btn btn-primary" onclick="openModal()">+ Nowy Task</button>
    <button class="btn btn-ghost" onclick="openAppModal()">⚙️ Aplikacje</button>
    <a href="/logout" class="btn btn-ghost">Wyloguj</a>
  </div>
</div>

<!-- BOARD -->
<div class="board" id="board"></div>

<!-- ADD/EDIT TASK MODAL -->
<div class="modal-overlay" id="taskModal">
  <div class="modal">
    <h2 id="modalTitle">Nowy Task</h2>
    <input type="hidden" id="taskId">
    <div class="form-group">
      <label>Tytuł</label>
      <input type="text" id="fTitle" placeholder="Krótki tytuł...">
    </div>
    <div class="form-group">
      <label>Opis</label>
      <textarea id="fDesc" rows="3" placeholder="Co trzeba zrobić..."></textarea>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Priorytet</label>
        <select id="fPriority">
          <option value="low">🟢 Low</option>
          <option value="medium" selected>🟡 Medium</option>
          <option value="high">🟠 High</option>
          <option value="critical">🔴 Critical</option>
        </select>
      </div>
      <div class="form-group">
        <label>Bucket</label>
        <select id="fBucket">
          {% for b in buckets_order %}
          <option value="{{ b }}">{{ bucket_labels[b] }}</option>
          {% endfor %}
        </select>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Aplikacja</label>
        <select id="fApp"><option value="">— brak —</option></select>
      </div>
      <div class="form-group">
        <label>Szacowany czas</label>
        <input type="text" id="fTime" placeholder="np. 2h, 30min">
      </div>
    </div>
    <div class="form-group">
      <label>Katalog aplikacji</label>
      <input type="text" id="fDir" placeholder="~/Documents/Coding_space-Python/...">
    </div>
    <div class="form-group">
      <label>Tagi (oddziel przecinkiem)</label>
      <input type="text" id="fTags" placeholder="refactor, security, ui">
    </div>
    <div class="form-group">
      <label>Komentarz (po wykonaniu)</label>
      <textarea id="fComment" rows="2" placeholder="Notatki..."></textarea>
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal()">Anuluj</button>
      <button class="btn btn-primary" onclick="saveTask()">Zapisz</button>
    </div>
  </div>
</div>

<!-- APP MANAGEMENT MODAL -->
<div class="modal-overlay" id="appModal">
  <div class="modal">
    <h2>Zarządzaj aplikacjami</h2>
    <div class="form-group">
      <label>Dodaj nową aplikację</label>
      <div style="display:flex;gap:8px">
        <input type="text" id="newAppName" placeholder="Nazwa aplikacji...">
        <button class="btn btn-primary" onclick="addApp()">Dodaj</button>
      </div>
    </div>
    <div id="appList" style="margin-top:12px"></div>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeAppModal()">Zamknij</button>
    </div>
  </div>
</div>

<script>
// ─── STATE ─────────────────────────────────
let STATE = {tasks:[], apps:[]};
const BUCKETS = {{ buckets_order | tojson }};
const LABELS = {{ bucket_labels | tojson }};
const COLORS = {{ bucket_colors | tojson }};

// ─── LOAD ──────────────────────────────────
async function load(){
  const r = await fetch('/api/tasks');
  STATE = await r.json();
  render();
}

// ─── RENDER ────────────────────────────────
function render(){
  const board = document.getElementById('board');
  board.innerHTML = '';
  
  BUCKETS.forEach(bucket => {
    const tasks = STATE.tasks
      .filter(t => t.bucket === bucket)
      .sort((a,b) => (a.order||999) - (b.order||999));
    
    const col = document.createElement('div');
    col.className = 'column';
    col.innerHTML = `
      <div class="column-header">
        <div class="column-title">
          <span class="column-dot" style="background:${COLORS[bucket]}"></span>
          ${LABELS[bucket]}
        </div>
        <span class="column-count">${tasks.length}</span>
      </div>
      <div class="column-body" data-bucket="${bucket}"></div>
    `;
    
    const body = col.querySelector('.column-body');
    
    // Drag & drop events on column
    body.addEventListener('dragover', e => { e.preventDefault(); body.classList.add('drag-over'); });
    body.addEventListener('dragleave', () => body.classList.remove('drag-over'));
    body.addEventListener('drop', e => { e.preventDefault(); body.classList.remove('drag-over'); handleDrop(e, bucket); });
    
    if(tasks.length === 0){
      body.innerHTML = '<div class="empty-placeholder">Przeciągnij tutaj...</div>';
    } else {
      tasks.forEach((t, idx) => {
        body.appendChild(createCard(t, idx));
      });
    }
    
    board.appendChild(col);
  });
  
  // Update app selects
  updateAppSelect();
}

function createCard(t, idx){
  const card = document.createElement('div');
  card.className = 'task-card';
  card.draggable = true;
  card.dataset.id = t.id;
  card.dataset.order = idx;
  
  card.addEventListener('dragstart', e => {
    e.dataTransfer.setData('text/plain', t.id);
    card.classList.add('dragging');
  });
  card.addEventListener('dragend', () => card.classList.remove('dragging'));
  
  // Priority badge
  const pLabel = {critical:'🔴 Critical',high:'🟠 High',medium:'🟡 Medium',low:'🟢 Low'}[t.priority] || t.priority;
  const pClass = 'priority-' + (t.priority || 'medium');
  
  let tagsHtml = (t.tags||[]).map(tag => `<span class="task-tag">${tag}</span>`).join('');
  if(t.app) tagsHtml += `<span class="task-app">${t.app}</span>`;
  
  let extraHtml = '';
  if(t.app_directory) extraHtml += `<div class="task-dir">📁 ${t.app_directory}</div>`;
  if(t.comment) extraHtml += `<div class="task-comment">💬 ${t.comment}</div>`;
  
  card.innerHTML = `
    <div class="task-actions">
      <button class="task-action-btn" onclick="editTask('${t.id}')" title="Edytuj">✏️</button>
      <button class="task-action-btn" onclick="deleteTask('${t.id}')" title="Usuń">🗑️</button>
    </div>
    <div class="task-title">${t.title || 'Untitled'}</div>
    ${t.description ? `<div class="task-desc">${t.description}</div>` : ''}
    ${tagsHtml ? `<div class="task-meta">${tagsHtml}</div>` : ''}
    <div class="task-footer">
      <span class="task-priority ${pClass}">${pLabel}</span>
      ${t.estimated_time ? `<span class="task-time">⏱ ${t.estimated_time}</span>` : ''}
      <span class="task-source">${t.source === 'copilot' ? '🤖' : '👤'}</span>
    </div>
    ${extraHtml}
  `;
  
  return card;
}

// ─── DRAG & DROP ───────────────────────────
async function handleDrop(e, targetBucket){
  const taskId = e.dataTransfer.getData('text/plain');
  if(!taskId) return;
  
  // Get all cards in target column and determine drop position
  const column = e.currentTarget;
  const cards = [...column.querySelectorAll('.task-card')];
  const afterCard = cards.find(c => {
    const box = c.getBoundingClientRect();
    return e.clientY < box.top + box.height / 2;
  });
  
  // Build new order for all tasks in target bucket
  const updates = [];
  
  // Move the task to target bucket
  const task = STATE.tasks.find(t => t.id === taskId);
  if(task) task.bucket = targetBucket;
  
  // Recalculate orders for target bucket
  const bucketTasks = STATE.tasks.filter(t => t.bucket === targetBucket).sort((a,b) => (a.order||999) - (b.order||999));
  
  // Remove dragged task and reinsert at position
  const filtered = bucketTasks.filter(t => t.id !== taskId);
  let insertIdx = afterCard ? filtered.findIndex(t => t.id === afterCard.dataset.id) : filtered.length;
  if(insertIdx < 0) insertIdx = filtered.length;
  filtered.splice(insertIdx, 0, task);
  
  filtered.forEach((t, i) => {
    t.order = i;
    updates.push({id: t.id, bucket: targetBucket, order: i});
  });
  
  render();
  
  await fetch('/api/reorder', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({updates})
  });
}

// ─── MODAL ─────────────────────────────────
function openModal(taskId){
  document.getElementById('taskModal').classList.add('active');
  
  if(taskId){
    const t = STATE.tasks.find(x => x.id === taskId);
    if(!t) return;
    document.getElementById('modalTitle').textContent = 'Edytuj Task';
    document.getElementById('taskId').value = t.id;
    document.getElementById('fTitle').value = t.title || '';
    document.getElementById('fDesc').value = t.description || '';
    document.getElementById('fPriority').value = t.priority || 'medium';
    document.getElementById('fBucket').value = t.bucket || 'manually-recommended';
    document.getElementById('fApp').value = t.app || '';
    document.getElementById('fTime').value = t.estimated_time || '';
    document.getElementById('fDir').value = t.app_directory || '';
    document.getElementById('fTags').value = (t.tags||[]).join(', ');
    document.getElementById('fComment').value = t.comment || '';
  } else {
    document.getElementById('modalTitle').textContent = 'Nowy Task';
    document.getElementById('taskId').value = '';
    document.getElementById('fTitle').value = '';
    document.getElementById('fDesc').value = '';
    document.getElementById('fPriority').value = 'medium';
    document.getElementById('fBucket').value = 'manually-recommended';
    document.getElementById('fApp').value = '';
    document.getElementById('fTime').value = '';
    document.getElementById('fDir').value = '';
    document.getElementById('fTags').value = '';
    document.getElementById('fComment').value = '';
  }
}

function closeModal(){
  document.getElementById('taskModal').classList.remove('active');
}

function editTask(id){ openModal(id); }

async function deleteTask(id){
  if(!confirm('Usunąć ten task?')) return;
  await fetch('/api/tasks/' + id, {method:'DELETE'});
  await load();
}

async function saveTask(){
  const id = document.getElementById('taskId').value;
  const body = {
    title: document.getElementById('fTitle').value,
    description: document.getElementById('fDesc').value,
    priority: document.getElementById('fPriority').value,
    bucket: document.getElementById('fBucket').value,
    app: document.getElementById('fApp').value,
    estimated_time: document.getElementById('fTime').value,
    app_directory: document.getElementById('fDir').value,
    tags: document.getElementById('fTags').value.split(',').map(s=>s.trim()).filter(Boolean),
    comment: document.getElementById('fComment').value,
    source: 'manual',
  };
  
  if(id){
    await fetch('/api/tasks/' + id, {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  } else {
    await fetch('/api/tasks', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  }
  
  closeModal();
  await load();
}

// ─── APP MANAGEMENT ────────────────────────
function updateAppSelect(){
  const sel = document.getElementById('fApp');
  const cur = sel.value;
  sel.innerHTML = '<option value="">— brak —</option>';
  (STATE.apps||[]).forEach(a => {
    sel.innerHTML += `<option value="${a}"${a===cur?' selected':''}>${a}</option>`;
  });
}

function openAppModal(){
  document.getElementById('appModal').classList.add('active');
  renderAppList();
}
function closeAppModal(){
  document.getElementById('appModal').classList.remove('active');
}

function renderAppList(){
  const list = document.getElementById('appList');
  list.innerHTML = (STATE.apps||[]).map(a => `<div style="padding:6px 0;border-bottom:1px solid #f1f5f9;font-size:14px">📱 ${a}</div>`).join('');
}

async function addApp(){
  const input = document.getElementById('newAppName');
  const name = input.value.trim();
  if(!name) return;
  await fetch('/api/apps', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name})});
  input.value = '';
  await load();
  renderAppList();
}

// ─── INIT ──────────────────────────────────
load();
</script>
</body></html>"""


# ──────────────────────────────────────────────
# Run
# ──────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
