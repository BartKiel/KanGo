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
        pw = request.form.get("password", "")
        if hashlib.sha256(pw.encode()).hexdigest() == PASSWORD_HASH:
            session["authed"] = True
            return redirect("/")
        error_div = '<div class="error">Nieprawid\u0142owe has\u0142o</div>'

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

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KanGo - Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh}
.login{background:#fff;border-radius:16px;padding:48px;width:380px;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.login h1{font-size:28px;font-weight:700;color:#1e293b;margin-bottom:8px;text-align:center}
.login p{color:#64748b;text-align:center;margin-bottom:32px;font-size:14px}
.login input{width:100%;padding:12px 16px;border:1px solid #e2e8f0;border-radius:8px;font-size:15px;margin-bottom:16px;outline:none}
.login input:focus{border-color:#3b82f6}
.login button{width:100%;padding:12px;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
.login button:hover{background:#2563eb}
.error{color:#ef4444;font-size:13px;text-align:center;margin-bottom:12px}
.logo{font-size:40px;text-align:center;margin-bottom:16px}
</style></head><body>
<form class="login" method="POST">
<div class="logo">&#x1F4CB;</div>
<h1>KanGo</h1>
<p>Lightweight Kanban for StratosX</p>
{{ERROR}}
<input type="password" name="password" placeholder="Has&#x142;o..." autofocus>
<button type="submit">Zaloguj si&#x119;</button>
</form></body></html>"""


BOARD_PAGE = r"""<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KanGo - Board</title>
<style>
:root{--bg:#f1f5f9;--card:#fff;--border:#e2e8f0;--text:#1e293b;--dim:#64748b;--blue:#3b82f6;--green:#10b981;--amber:#f59e0b;--red:#ef4444;--purple:#8b5cf6;--indigo:#6366f1}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);overflow-x:auto}
.topbar{background:#fff;border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.topbar h1{font-size:20px;font-weight:700;display:flex;align-items:center;gap:8px}
.topbar-actions{display:flex;gap:8px;align-items:center}
.btn{padding:8px 16px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:none;transition:all .2s;display:flex;align-items:center;gap:6px}
.btn-primary{background:var(--blue);color:#fff}.btn-primary:hover{background:#2563eb}
.btn-ghost{background:transparent;color:var(--dim);border:1px solid var(--border)}.btn-ghost:hover{background:#f8fafc}
.board{display:flex;gap:16px;padding:20px 24px;min-height:calc(100vh - 60px);align-items:flex-start;overflow-x:auto}
.column{min-width:280px;max-width:320px;flex:1;background:#fff;border-radius:12px;border:1px solid var(--border);display:flex;flex-direction:column;max-height:calc(100vh - 100px)}
.col-head{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.col-title{font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px}
.col-count{background:#f1f5f9;color:var(--dim);font-size:11px;font-weight:600;padding:2px 8px;border-radius:10px}
.col-dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.col-body{padding:8px;flex:1;overflow-y:auto;min-height:60px}
.col-body.drag-over{background:#eff6ff}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:8px;cursor:grab;transition:all .15s;position:relative}
.card:hover{box-shadow:0 2px 8px rgba(0,0,0,.06);border-color:#cbd5e1}
.card:active{cursor:grabbing;opacity:.8}
.card.dragging{opacity:.4;transform:scale(.95)}
.card-title{font-size:14px;font-weight:600;margin-bottom:6px;line-height:1.3}
.card-desc{font-size:12px;color:var(--dim);margin-bottom:8px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.card-meta{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px}
.tag{font-size:11px;padding:2px 8px;border-radius:6px;background:#f1f5f9;color:var(--dim);font-weight:500}
.tag-app{background:#eff6ff;color:var(--blue)}
.card-foot{display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--dim)}
.prio{font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px}
.p-critical{background:#fef2f2;color:var(--red)}
.p-high{background:#fff7ed;color:#ea580c}
.p-medium{background:#fefce8;color:#ca8a04}
.p-low{background:#f0fdf4;color:var(--green)}
.card-time{font-size:11px;color:var(--purple);font-weight:500}
.card-comment{font-size:11px;color:var(--green);margin-top:4px;font-style:italic}
.card-dir{font-size:10px;color:var(--dim);font-family:monospace;margin-top:4px;background:#f8fafc;padding:2px 6px;border-radius:4px;display:inline-block}
.card-actions{position:absolute;top:8px;right:8px;display:none;gap:4px}
.card:hover .card-actions{display:flex}
.act-btn{width:24px;height:24px;border-radius:6px;border:none;background:#f1f5f9;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center}
.act-btn:hover{background:#e2e8f0}
.modal-bg{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.4);z-index:200;display:none;align-items:center;justify-content:center}
.modal-bg.active{display:flex}
.modal{background:#fff;border-radius:16px;padding:32px;width:520px;max-width:90vw;max-height:85vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,.15)}
.modal h2{font-size:20px;font-weight:700;margin-bottom:20px}
.fg{margin-bottom:16px}
.fg label{display:block;font-size:13px;font-weight:600;color:var(--dim);margin-bottom:6px}
.fg input,.fg textarea,.fg select{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:8px;font-size:14px;font-family:inherit;outline:none}
.fg input:focus,.fg textarea:focus,.fg select:focus{border-color:var(--blue)}
.fg textarea{resize:vertical;min-height:60px}
.fr{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.modal-foot{display:flex;gap:8px;justify-content:flex-end;margin-top:24px}
.empty{text-align:center;padding:24px;color:#cbd5e1;font-size:13px}
</style></head><body>
<div class="topbar">
<h1>&#x1F4CB; KanGo</h1>
<div class="topbar-actions">
<button class="btn btn-primary" onclick="openModal()">+ Nowy Task</button>
<button class="btn btn-ghost" onclick="openAppModal()">&#x2699;&#xFE0F; Aplikacje</button>
<a href="/logout" class="btn btn-ghost">Wyloguj</a>
</div></div>
<div class="board" id="board"></div>

<!-- TASK MODAL -->
<div class="modal-bg" id="taskModal"><div class="modal">
<h2 id="mTitle">Nowy Task</h2>
<input type="hidden" id="taskId">
<div class="fg"><label>Tytu&#x142;</label><input id="fTitle" placeholder="Kr&oacute;tki tytu&#x142;..."></div>
<div class="fg"><label>Opis</label><textarea id="fDesc" rows="3" placeholder="Co trzeba zrobi&#x107;..."></textarea></div>
<div class="fr">
<div class="fg"><label>Priorytet</label><select id="fPriority"><option value="low">&#x1F7E2; Low</option><option value="medium" selected>&#x1F7E1; Medium</option><option value="high">&#x1F7E0; High</option><option value="critical">&#x1F534; Critical</option></select></div>
<div class="fg"><label>Bucket</label><select id="fBucket">__BUCKET_OPTIONS__</select></div>
</div>
<div class="fr">
<div class="fg"><label>Aplikacja</label><select id="fApp"><option value="">&#x2014; brak &#x2014;</option></select></div>
<div class="fg"><label>Szacowany czas</label><input id="fTime" placeholder="np. 2h, 30min"></div>
</div>
<div class="fg"><label>Katalog aplikacji</label><input id="fDir" placeholder="~/Documents/Coding_space-Python/..."></div>
<div class="fg"><label>Tagi (przecinkiem)</label><input id="fTags" placeholder="refactor, security, ui"></div>
<div class="fg"><label>Komentarz</label><textarea id="fComment" rows="2" placeholder="Notatki..."></textarea></div>
<div class="modal-foot">
<button class="btn btn-ghost" onclick="closeModal()">Anuluj</button>
<button class="btn btn-primary" onclick="saveTask()">Zapisz</button>
</div></div></div>

<!-- APP MODAL -->
<div class="modal-bg" id="appModal"><div class="modal">
<h2>Zarz&#x105;dzaj aplikacjami</h2>
<div class="fg"><label>Dodaj now&#x105; aplikacj&#x119;</label>
<div style="display:flex;gap:8px"><input id="newAppName" placeholder="Nazwa..."><button class="btn btn-primary" onclick="addApp()">Dodaj</button></div></div>
<div id="appList" style="margin-top:12px"></div>
<div class="modal-foot"><button class="btn btn-ghost" onclick="closeAppModal()">Zamknij</button></div>
</div></div>

<script>
var S={tasks:[],apps:[]};
var BUCKETS=__BUCKETS_JSON__;
var LABELS=__LABELS_JSON__;
var COLORS=__COLORS_JSON__;

function load(){
  fetch("/api/tasks").then(function(r){return r.json()}).then(function(d){S=d;render()}).catch(function(e){console.error(e);render()});
}

function render(){
  var b=document.getElementById("board");
  b.innerHTML="";
  BUCKETS.forEach(function(bk){
    var tasks=S.tasks.filter(function(t){return t.bucket===bk}).sort(function(a,b){return(a.order||999)-(b.order||999)});
    var col=document.createElement("div");col.className="column";
    var hd=document.createElement("div");hd.className="col-head";
    hd.innerHTML='<div class="col-title"><span class="col-dot" style="background:'+COLORS[bk]+'"></span>'+LABELS[bk]+'</div><span class="col-count">'+tasks.length+'</span>';
    col.appendChild(hd);
    var body=document.createElement("div");body.className="col-body";body.setAttribute("data-bucket",bk);
    body.addEventListener("dragover",function(e){e.preventDefault();body.classList.add("drag-over")});
    body.addEventListener("dragleave",function(){body.classList.remove("drag-over")});
    body.addEventListener("drop",function(e){e.preventDefault();body.classList.remove("drag-over");onDrop(e,bk)});
    if(!tasks.length){body.innerHTML='<div class="empty">Przeci&#x105;gnij tutaj...</div>'}
    else{tasks.forEach(function(t){body.appendChild(mkCard(t))})}
    col.appendChild(body);b.appendChild(col);
  });
  updAppSel();
}

function esc(s){var d=document.createElement("div");d.textContent=s;return d.innerHTML}

function mkCard(t){
  var c=document.createElement("div");c.className="card";c.draggable=true;c.setAttribute("data-id",t.id);
  c.addEventListener("dragstart",function(e){e.dataTransfer.setData("text/plain",t.id);c.classList.add("dragging")});
  c.addEventListener("dragend",function(){c.classList.remove("dragging")});
  var pl={critical:"\ud83d\udd34 Critical",high:"\ud83d\udfe0 High",medium:"\ud83d\udfe1 Medium",low:"\ud83d\udfe2 Low"};
  var h='<div class="card-actions"><button class="act-btn" onclick="editTask(\''+t.id+'\')" title="Edytuj">\u270f\ufe0f</button><button class="act-btn" onclick="delTask(\''+t.id+'\')" title="Usu\u0144">\ud83d\uddd1\ufe0f</button></div>';
  h+='<div class="card-title">'+esc(t.title||"Untitled")+'</div>';
  if(t.description)h+='<div class="card-desc">'+esc(t.description)+'</div>';
  var tags="";(t.tags||[]).forEach(function(g){tags+='<span class="tag">'+esc(g)+'</span>'});
  if(t.app)tags+='<span class="tag tag-app">'+esc(t.app)+'</span>';
  if(tags)h+='<div class="card-meta">'+tags+'</div>';
  h+='<div class="card-foot"><span class="prio p-'+(t.priority||"medium")+'">'+(pl[t.priority]||t.priority)+'</span>';
  if(t.estimated_time)h+='<span class="card-time">\u23f1 '+esc(t.estimated_time)+'</span>';
  h+='<span style="font-size:10px;opacity:.6">'+(t.source==="copilot"?"\ud83e\udd16":"\ud83d\udc64")+'</span></div>';
  if(t.app_directory)h+='<div class="card-dir">\ud83d\udcc1 '+esc(t.app_directory)+'</div>';
  if(t.comment)h+='<div class="card-comment">\ud83d\udcac '+esc(t.comment)+'</div>';
  c.innerHTML=h;return c;
}

function onDrop(e,bucket){
  var id=e.dataTransfer.getData("text/plain");if(!id)return;
  var task=S.tasks.find(function(t){return t.id===id});if(task)task.bucket=bucket;
  var bt=S.tasks.filter(function(t){return t.bucket===bucket}).sort(function(a,b){return(a.order||999)-(b.order||999)});
  var ups=[];bt.forEach(function(t,i){t.order=i;ups.push({id:t.id,bucket:bucket,order:i})});
  render();
  fetch("/api/reorder",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({updates:ups})});
}

function openModal(id){
  document.getElementById("taskModal").classList.add("active");
  if(id){
    var t=S.tasks.find(function(x){return x.id===id});if(!t)return;
    document.getElementById("mTitle").textContent="Edytuj Task";
    document.getElementById("taskId").value=t.id;
    document.getElementById("fTitle").value=t.title||"";
    document.getElementById("fDesc").value=t.description||"";
    document.getElementById("fPriority").value=t.priority||"medium";
    document.getElementById("fBucket").value=t.bucket||"manually-recommended";
    document.getElementById("fApp").value=t.app||"";
    document.getElementById("fTime").value=t.estimated_time||"";
    document.getElementById("fDir").value=t.app_directory||"";
    document.getElementById("fTags").value=(t.tags||[]).join(", ");
    document.getElementById("fComment").value=t.comment||"";
  }else{
    document.getElementById("mTitle").textContent="Nowy Task";
    ["taskId","fTitle","fDesc","fTime","fDir","fTags","fComment"].forEach(function(x){document.getElementById(x).value=""});
    document.getElementById("fPriority").value="medium";
    document.getElementById("fBucket").value="manually-recommended";
    document.getElementById("fApp").value="";
  }
}
function closeModal(){document.getElementById("taskModal").classList.remove("active")}
function editTask(id){openModal(id)}
function delTask(id){if(!confirm("Usun\u0105\u0107 ten task?"))return;fetch("/api/tasks/"+id,{method:"DELETE"}).then(load)}
function saveTask(){
  var id=document.getElementById("taskId").value;
  var body={title:document.getElementById("fTitle").value,description:document.getElementById("fDesc").value,priority:document.getElementById("fPriority").value,bucket:document.getElementById("fBucket").value,app:document.getElementById("fApp").value,estimated_time:document.getElementById("fTime").value,app_directory:document.getElementById("fDir").value,tags:document.getElementById("fTags").value.split(",").map(function(s){return s.trim()}).filter(Boolean),comment:document.getElementById("fComment").value,source:"manual"};
  var url=id?"/api/tasks/"+id:"/api/tasks";
  var method=id?"PUT":"POST";
  fetch(url,{method:method,headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}).then(function(){closeModal();load()});
}
function updAppSel(){
  var s=document.getElementById("fApp");var v=s.value;
  s.innerHTML='<option value="">\u2014 brak \u2014</option>';
  (S.apps||[]).forEach(function(a){var o=document.createElement("option");o.value=a;o.textContent=a;if(a===v)o.selected=true;s.appendChild(o)});
}
function openAppModal(){document.getElementById("appModal").classList.add("active");renderApps()}
function closeAppModal(){document.getElementById("appModal").classList.remove("active")}
function renderApps(){document.getElementById("appList").innerHTML=(S.apps||[]).map(function(a){return'<div style="padding:6px 0;border-bottom:1px solid #f1f5f9;font-size:14px">\ud83d\udcf1 '+esc(a)+'</div>'}).join("")}
function addApp(){var i=document.getElementById("newAppName");var n=i.value.trim();if(!n)return;fetch("/api/apps",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:n})}).then(function(){i.value="";load();renderApps()})}

load();
</script></body></html>"""


# ──────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
