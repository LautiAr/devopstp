"""
Task API — Versión básica del TP de DevOps.

CRUD simple en memoria. Sin base de datos, sin autenticación.
"""

import os
from datetime import datetime, timezone

from flask import Flask, abort, jsonify, request

try:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration

    SENTRY_DSN = os.environ.get("SENTRY_DSN", "")
    if SENTRY_DSN:
        sentry_sdk.init(
            dsn=SENTRY_DSN,
            integrations=[FlaskIntegration()],
            traces_sample_rate=1.0,
        )
except ImportError:
    SENTRY_DSN = ""


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def create_app(config=None):
    app = Flask(__name__)

    # "Base de datos" en memoria.
    app.config["TASKS"] = {}
    app.config["NEXT_ID"] = 1

    if config:
        app.config.update(config)

    def _next_id():
        nid = app.config["NEXT_ID"]
        app.config["NEXT_ID"] = nid + 1
        return nid

    # ── Index ────────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return jsonify(
            {
                "api": "Task API",
                "version": "1.0",
                "endpoints": {
                    "GET /": "Esta página",
                    "GET /health": "Healthcheck",
                    "GET /metrics": "Métricas básicas",
                    "GET /tasks": "Listar tareas",
                    "POST /tasks": "Crear tarea",
                    "GET /tasks/<id>": "Ver una tarea",
                    "PATCH /tasks/<id>": "Actualizar tarea",
                    "DELETE /tasks/<id>": "Eliminar tarea",
                },
            }
        ), 200

    # ── Healthcheck (para Docker y Render) ────────────────────────────────
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "timestamp": now_iso()}), 200

    # ── Métricas básicas (Second Way: visibilidad/feedback) ───────────────
    @app.route("/metrics")
    def metrics():
        tasks = app.config["TASKS"].values()
        total = len(tasks)
        done = sum(1 for t in tasks if t["done"])
        return jsonify(
            {
                "total": total,
                "done": done,
                "pending": total - done,
                "completion_pct": round(done / total * 100, 1) if total else 0,
            }
        ), 200

    # ── Tasks ─────────────────────────────────────────────────────────────
    @app.route("/tasks", methods=["GET"])
    def list_tasks():
        return jsonify(list(app.config["TASKS"].values())), 200

    @app.route("/tasks", methods=["POST"])
    def create_task():
        data = request.get_json(silent=True) or {}
        title = data.get("title", "").strip()
        if not title:
            abort(400, description="'title' es requerido")

        task = {
            "id": _next_id(),
            "title": title,
            "done": bool(data.get("done", False)),
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
        app.config["TASKS"][task["id"]] = task
        return jsonify(task), 201

    @app.route("/tasks/<int:task_id>", methods=["GET"])
    def get_task(task_id):
        task = app.config["TASKS"].get(task_id)
        if not task:
            abort(404)
        return jsonify(task), 200

    @app.route("/tasks/<int:task_id>", methods=["PATCH"])
    def update_task(task_id):
        task = app.config["TASKS"].get(task_id)
        if not task:
            abort(404)
        data = request.get_json(silent=True) or {}
        if "title" in data:
            title = data["title"].strip()
            if not title:
                abort(400, description="'title' no puede estar vacío")
            task["title"] = title
        if "done" in data:
            task["done"] = bool(data["done"])
        task["updated_at"] = now_iso()
        return jsonify(task), 200

    @app.route("/tasks/<int:task_id>", methods=["DELETE"])
    def delete_task(task_id):
        task = app.config["TASKS"].pop(task_id, None)
        if not task:
            abort(404)
        return jsonify({"message": f"Tarea {task_id} eliminada"}), 200

    # ── Error handlers ────────────────────────────────────────────────────
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad request", "detail": str(e.description)}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
