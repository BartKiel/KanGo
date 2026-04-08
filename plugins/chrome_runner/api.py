"""
KanGo Chrome Runner – Flask API Blueprint
──────────────────────────────────────────
Mount in KanGo app.py to expose plugin management via REST API.

Usage in app.py:
    from plugins.chrome_runner.api import chrome_bp
    app.register_blueprint(chrome_bp, url_prefix="/api/chrome")

Endpoints:
    GET  /api/chrome/plugins          → list registered plugins
    GET  /api/chrome/status           → running sessions
    POST /api/chrome/launch           → { "plugins": ["sov_listener"] }
    POST /api/chrome/stop             → { "profile": "stratosx_harvest" }
    POST /api/chrome/stop-all         → stop everything
"""

from flask import Blueprint, jsonify, request

chrome_bp = Blueprint("chrome_runner", __name__)

# Lazy singleton — only created when API is first called
_runner = None


def _get_runner():
    global _runner
    if _runner is None:
        from .runner import ChromeRunner
        _runner = ChromeRunner()
    return _runner


@chrome_bp.route("/plugins", methods=["GET"])
def api_list_plugins():
    runner = _get_runner()
    plugins = [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "path": str(p.path),
            "start_url": p.start_url,
            "profile": p.profile,
            "enabled": p.enabled,
        }
        for p in runner.list_plugins()
    ]
    return jsonify({"plugins": plugins})


@chrome_bp.route("/status", methods=["GET"])
def api_status():
    runner = _get_runner()
    return jsonify({"sessions": runner.status()})


@chrome_bp.route("/launch", methods=["POST"])
def api_launch():
    runner = _get_runner()
    data = request.get_json(force=True)
    plugin_ids = data.get("plugins", [])
    start_url = data.get("start_url", "")

    if not plugin_ids:
        return jsonify({"error": "No plugins specified"}), 400

    try:
        session = runner.launch(
            plugin_ids,
            start_url=start_url,
        )
        return jsonify({
            "ok": True,
            "profile": session.profile,
            "pid": session.pid,
            "plugins": [p.name for p in session.plugins],
        })
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@chrome_bp.route("/stop", methods=["POST"])
def api_stop():
    runner = _get_runner()
    data = request.get_json(force=True)
    profile = data.get("profile", "")
    if not profile:
        return jsonify({"error": "No profile specified"}), 400
    ok = runner.stop(profile)
    return jsonify({"ok": ok, "profile": profile})


@chrome_bp.route("/stop-all", methods=["POST"])
def api_stop_all():
    runner = _get_runner()
    runner.stop()
    return jsonify({"ok": True, "message": "All sessions stopped"})
