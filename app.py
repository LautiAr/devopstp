import os
import secrets
import string
import re
from datetime import datetime, timezone
from dotenv import load_dotenv

import bcrypt
import sentry_sdk
from cryptography.fernet import Fernet
from flask import Flask, jsonify, request, abort, g
from flask_sqlalchemy import SQLAlchemy
from sentry_sdk.integrations.flask import FlaskIntegration

# ── Sentry ────────────────────────────────────────────────────────────────────
load_dotenv()

SENTRY_DSN = os.environ.get("SENTRY_DSN", "")



if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[FlaskIntegration()],
        traces_sample_rate=1.0,       # capture 100 % of transactions
        profiles_sample_rate=1.0,
        send_default_pii=False,        # never send raw passwords
    )

# ── DB ────────────────────────────────────────────────────────────────────────
db = SQLAlchemy()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _fernet(app) -> Fernet:
    """Return (or lazily create) the Fernet cipher tied to the app."""
    if "_fernet" not in app.extensions:
        key = app.config.get("") or Fernet.generate_key()
        app.config["FERNET_KEY"] = key
        app.extensions["_fernet"] = Fernet(key)
    return app.extensions["_fernet"]


def encrypt(app, plaintext: str) -> str:
    return _fernet(app).encrypt(plaintext.encode()).decode()


def decrypt(app, token: str) -> str:
    return _fernet(app).decrypt(token.encode()).decode()


def now_utc():
    return datetime.now(timezone.utc)


PASSWORD_STRENGTH_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{12,}$"
)


def check_strength(password: str) -> dict:
    """
    Lean: weak passwords are waste — flag them before they enter the system.
    Returns {"strong": bool, "issues": [...]}
    """
    issues = []
    if len(password) < 12:
        issues.append("Minimum 12 characters required")
    if not re.search(r"[A-Z]", password):
        issues.append("At least one uppercase letter required")
    if not re.search(r"[a-z]", password):
        issues.append("At least one lowercase letter required")
    if not re.search(r"\d", password):
        issues.append("At least one digit required")
    if not re.search(r"[^a-zA-Z\d]", password):
        issues.append("At least one special character required")
    return {"strong": len(issues) == 0, "issues": issues}


def generate_password(length=20, use_symbols=True) -> str:
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    # Guarantee at least one of each required class
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?") if use_symbols else secrets.choice(string.digits),
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - len(pwd))]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


# ── Models ────────────────────────────────────────────────────────────────────

class Vault(db.Model):
    """
    A vault belongs to a user (identified by master_hash).
    Agile analogy: a Vault is a Sprint — it groups related entries.
    """
    __tablename__ = "vaults"
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(100), nullable=False)
    owner         = db.Column(db.String(100), nullable=False)
    master_hash   = db.Column(db.String(200), nullable=False)  # bcrypt
    created_at    = db.Column(db.DateTime, default=now_utc)
    entries       = db.relationship("Entry", backref="vault", lazy=True,
                                    cascade="all, delete-orphan")

    def to_dict(self, include_entries=False):
        d = {
            "id": self.id, "name": self.name, "owner": self.owner,
            "created_at": self.created_at.isoformat(),
            "entry_count": len(self.entries),
        }
        if include_entries:
            d["entries"] = [e.to_dict() for e in self.entries]
        return d


class Entry(db.Model):
    """
    A stored credential. Password is AES-256 encrypted at rest.
    Lean: strength_score < 3 = waste (flagged in /metrics).
    """
    __tablename__ = "entries"
    id              = db.Column(db.Integer, primary_key=True)
    vault_id        = db.Column(db.Integer, db.ForeignKey("vaults.id"), nullable=False)
    service         = db.Column(db.String(200), nullable=False)
    username        = db.Column(db.String(200), nullable=False)
    encrypted_pass  = db.Column(db.Text, nullable=False)
    strength_score  = db.Column(db.Integer, default=0)   # 0-5
    notes           = db.Column(db.Text, default="")
    created_at      = db.Column(db.DateTime, default=now_utc)
    updated_at      = db.Column(db.DateTime, default=now_utc, onupdate=now_utc)

    def to_dict(self, reveal=False, app=None):
        d = {
            "id": self.id, "vault_id": self.vault_id,
            "service": self.service, "username": self.username,
            "strength_score": self.strength_score,
            "strength_label": _strength_label(self.strength_score),
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        if reveal and app:
            d["password"] = decrypt(app, self.encrypted_pass)
        return d


class AuditLog(db.Model):
    """
    Third Way – Continual Learning: every sensitive action is logged.
    Provides the feedback loop for retrospectives and incident analysis.
    """
    __tablename__ = "audit_logs"
    id         = db.Column(db.Integer, primary_key=True)
    action     = db.Column(db.String(100), nullable=False)
    vault_id   = db.Column(db.Integer, nullable=True)
    entry_id   = db.Column(db.Integer, nullable=True)
    detail     = db.Column(db.String(500), default="")
    ip         = db.Column(db.String(50), default="")
    created_at = db.Column(db.DateTime, default=now_utc)

    def to_dict(self):
        return {
            "id": self.id, "action": self.action,
            "vault_id": self.vault_id, "entry_id": self.entry_id,
            "detail": self.detail, "ip": self.ip,
            "created_at": self.created_at.isoformat(),
        }


class AndonEvent(db.Model):
    """Andon Cord – halt the line on critical security failures."""
    __tablename__ = "andon_events"
    id          = db.Column(db.Integer, primary_key=True)
    severity    = db.Column(db.String(10), default="high")
    message     = db.Column(db.String(500), nullable=False)
    resolved    = db.Column(db.Boolean, default=False)
    raised_at   = db.Column(db.DateTime, default=now_utc)
    resolved_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id, "severity": self.severity, "message": self.message,
            "resolved": self.resolved,
            "raised_at": self.raised_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _strength_label(score: int) -> str:
    return {0: "very_weak", 1: "weak", 2: "fair", 3: "good",
            4: "strong", 5: "very_strong"}.get(score, "unknown")


def _score_password(password: str) -> int:
    score = 0
    if len(password) >= 12: score += 1
    if len(password) >= 20: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"\d", password):    score += 1
    if re.search(r"[^a-zA-Z\d]", password): score += 1
    return score


def _audit(action, vault_id=None, entry_id=None, detail=""):
    log = AuditLog(
        action=action, vault_id=vault_id, entry_id=entry_id,
        detail=detail, ip=request.remote_addr or "",
    )
    db.session.add(log)


def _verify_master(vault: Vault, master: str) -> bool:
    return bcrypt.checkpw(master.encode(), vault.master_hash.encode())


# ── App factory ───────────────────────────────────────────────────────────────

def create_app(config=None):
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///passmanager.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["ANDON_ACTIVE"] = False
    app.config["FERNET_KEY"] = os.environ.get("FERNET_KEY", Fernet.generate_key())

    if config:
        app.config.update(config)

    db.init_app(app)
    with app.app_context():
        db.create_all()

    _register_routes(app, db)
    return app


# ── Routes ────────────────────────────────────────────────────────────────────

def _register_routes(app, db):

    # ── Andon gate ────────────────────────────────────────────────────────────
    @app.before_request
    def andon_gate():
        if not app.config.get("ANDON_ACTIVE"):
            return
        if request.method in ("GET", "HEAD"):
            return
        if request.path.startswith("/andon/"):
            return
        return jsonify({
            "error": "Andon cord active – writes halted",
            "concept": "Andon Cord / First Way: stop the line to protect quality",
        }), 503

    # ── Index ─────────────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return jsonify({
            "api": "Password Manager",
            "version": "1.0",
            "devops_concepts": {
                "three_ways": {
                    "first":  "Flow – fast, reliable delivery (Lean strength checks, encryption pipeline)",
                    "second": "Feedback – /metrics + Sentry error tracking",
                    "third":  "Continual Learning – full audit log at /audit",
                },
                "andon_cord": "POST /andon/pull → halt writes on critical failure",
                "agile":      "Vaults = Sprints, Entries = User Stories",
                "lean":       "Weak passwords flagged as waste in /metrics",
            },
            "endpoints": {
                "POST /vaults":                       "Create vault",
                "GET  /vaults/<id>":                  "Get vault (requires master password header)",
                "DELETE /vaults/<id>":                "Delete vault",
                "GET  /vaults/<id>/entries":          "List entries",
                "POST /vaults/<id>/entries":          "Store new credential",
                "GET  /vaults/<id>/entries/<eid>":    "Retrieve entry (optionally reveal password)",
                "PATCH /vaults/<id>/entries/<eid>":   "Update entry",
                "DELETE /vaults/<id>/entries/<eid>":  "Delete entry",
                "POST /generate":                     "Generate a strong password",
                "POST /check-strength":               "Check password strength",
                "GET  /metrics":                      "Lean/Agile/Security metrics",
                "GET  /audit":                        "Full audit log (Third Way)",
                "POST /andon/pull":                   "Pull Andon cord",
                "POST /andon/resolve/<id>":           "Resolve alert",
                "GET  /andon/events":                 "Andon event history",
            },
        })

    # ── Vaults ────────────────────────────────────────────────────────────────
    @app.route("/vaults", methods=["POST"])
    def create_vault():
        data = request.get_json(silent=True) or {}
        for field in ("name", "owner", "master_password"):
            if not data.get(field):
                abort(400, description=f"'{field}' is required")

        hashed = bcrypt.hashpw(data["master_password"].encode(), bcrypt.gensalt()).decode()
        vault = Vault(name=data["name"], owner=data["owner"], master_hash=hashed)
        db.session.add(vault)
        db.session.flush()
        _audit("vault_created", vault_id=vault.id, detail=f"owner={data['owner']}")
        db.session.commit()
        return jsonify(vault.to_dict()), 201

    @app.route("/vaults/<int:vault_id>", methods=["GET"])
    def get_vault(vault_id):
        vault = db.get_or_404(Vault, vault_id)
        master = request.headers.get("X-Master-Password", "")
        if not _verify_master(vault, master):
            _audit("vault_access_denied", vault_id=vault_id)
            db.session.commit()
            abort(401)
        _audit("vault_accessed", vault_id=vault_id)
        db.session.commit()
        return jsonify(vault.to_dict(include_entries=True)), 200

    @app.route("/vaults/<int:vault_id>", methods=["DELETE"])
    def delete_vault(vault_id):
        vault = db.get_or_404(Vault, vault_id)
        master = request.headers.get("X-Master-Password", "")
        if not _verify_master(vault, master):
            abort(401)
        _audit("vault_deleted", vault_id=vault_id, detail=f"name={vault.name}")
        db.session.delete(vault)
        db.session.commit()
        return jsonify({"message": f"Vault {vault_id} deleted"}), 200

    # ── Entries ───────────────────────────────────────────────────────────────
    @app.route("/vaults/<int:vault_id>/entries", methods=["GET"])
    def list_entries(vault_id):
        vault = db.get_or_404(Vault, vault_id)
        master = request.headers.get("X-Master-Password", "")
        if not _verify_master(vault, master):
            abort(401)
        return jsonify([e.to_dict() for e in vault.entries]), 200

    @app.route("/vaults/<int:vault_id>/entries", methods=["POST"])
    def create_entry(vault_id):
        vault = db.get_or_404(Vault, vault_id)
        master = request.headers.get("X-Master-Password", "")
        if not _verify_master(vault, master):
            abort(401)

        data = request.get_json(silent=True) or {}
        for field in ("service", "username", "password"):
            if not data.get(field):
                abort(400, description=f"'{field}' is required")

        strength = check_strength(data["password"])
        score    = _score_password(data["password"])

        entry = Entry(
            vault_id=vault_id,
            service=data["service"],
            username=data["username"],
            encrypted_pass=encrypt(app, data["password"]),
            strength_score=score,
            notes=data.get("notes", ""),
        )
        db.session.add(entry)
        db.session.flush()
        _audit("entry_created", vault_id=vault_id, entry_id=entry.id,
               detail=f"service={data['service']} strength={score}")
        db.session.commit()

        resp = entry.to_dict()
        resp["strength_check"] = strength
        return jsonify(resp), 201

    @app.route("/vaults/<int:vault_id>/entries/<int:entry_id>", methods=["GET"])
    def get_entry(vault_id, entry_id):
        vault = db.get_or_404(Vault, vault_id)
        master = request.headers.get("X-Master-Password", "")
        if not _verify_master(vault, master):
            abort(401)

        entry = db.get_or_404(Entry, entry_id)
        if entry.vault_id != vault_id:
            abort(404)

        reveal = request.args.get("reveal", "false").lower() == "true"
        _audit("entry_accessed", vault_id=vault_id, entry_id=entry_id,
               detail=f"reveal={reveal}")
        db.session.commit()
        return jsonify(entry.to_dict(reveal=reveal, app=app)), 200

    @app.route("/vaults/<int:vault_id>/entries/<int:entry_id>", methods=["PATCH"])
    def update_entry(vault_id, entry_id):
        vault = db.get_or_404(Vault, vault_id)
        master = request.headers.get("X-Master-Password", "")
        if not _verify_master(vault, master):
            abort(401)

        entry = db.get_or_404(Entry, entry_id)
        if entry.vault_id != vault_id:
            abort(404)

        data = request.get_json(silent=True) or {}
        if "service"  in data: entry.service  = data["service"]
        if "username" in data: entry.username  = data["username"]
        if "notes"    in data: entry.notes     = data["notes"]
        if "password" in data:
            entry.encrypted_pass  = encrypt(app, data["password"])
            entry.strength_score  = _score_password(data["password"])
        entry.updated_at = now_utc()

        _audit("entry_updated", vault_id=vault_id, entry_id=entry_id)
        db.session.commit()
        return jsonify(entry.to_dict()), 200

    @app.route("/vaults/<int:vault_id>/entries/<int:entry_id>", methods=["DELETE"])
    def delete_entry(vault_id, entry_id):
        vault = db.get_or_404(Vault, vault_id)
        master = request.headers.get("X-Master-Password", "")
        if not _verify_master(vault, master):
            abort(401)

        entry = db.get_or_404(Entry, entry_id)
        if entry.vault_id != vault_id:
            abort(404)

        _audit("entry_deleted", vault_id=vault_id, entry_id=entry_id,
               detail=f"service={entry.service}")
        db.session.delete(entry)
        db.session.commit()
        return jsonify({"message": f"Entry {entry_id} deleted"}), 200

    # ── Password utilities ────────────────────────────────────────────────────
    @app.route("/generate", methods=["POST"])
    def generate():
        data = request.get_json(silent=True) or {}
        length      = min(max(int(data.get("length", 20)), 12), 128)
        use_symbols = bool(data.get("symbols", True))
        pwd = generate_password(length, use_symbols)
        return jsonify({
            "password": pwd,
            "length": len(pwd),
            "strength": check_strength(pwd),
            "score": _score_password(pwd),
        }), 200

    @app.route("/check-strength", methods=["POST"])
    def check_strength_route():
        data = request.get_json(silent=True) or {}
        pwd = data.get("password", "")
        if not pwd:
            abort(400, description="'password' is required")
        result = check_strength(pwd)
        result["score"] = _score_password(pwd)
        result["label"] = _strength_label(result["score"])
        return jsonify(result), 200

    # ── Metrics (Second Way – Feedback) ───────────────────────────────────────
    @app.route("/metrics", methods=["GET"])
    def metrics():
        total_entries = Entry.query.count()
        weak_entries  = Entry.query.filter(Entry.strength_score < 3).count()
        total_vaults  = Vault.query.count()
        total_audits  = AuditLog.query.count()
        open_andon    = AndonEvent.query.filter_by(resolved=False).count()

        by_strength = {}
        for score in range(6):
            label = _strength_label(score)
            by_strength[label] = Entry.query.filter_by(strength_score=score).count()

        recent_audits = (AuditLog.query
                         .order_by(AuditLog.created_at.desc())
                         .limit(5).all())

        return jsonify({
            "concept": "Second Way – Feedback & visibility",
            "vaults": total_vaults,
            "entries": {
                "total": total_entries,
                "by_strength": by_strength,
            },
            "lean": {
                "weak_entries": weak_entries,
                "waste_pct": round(weak_entries / total_entries * 100, 1) if total_entries else 0,
                "note": "Lean: weak passwords are waste – flag and remediate",
            },
            "security": {
                "audit_events": total_audits,
                "open_andon_alerts": open_andon,
                "andon_active": app.config.get("ANDON_ACTIVE", False),
            },
            "recent_activity": [a.to_dict() for a in recent_audits],
        }), 200

    # ── Audit log (Third Way) ─────────────────────────────────────────────────
    @app.route("/audit", methods=["GET"])
    def audit_log():
        logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
        return jsonify({
            "concept": "Third Way – Continual Learning",
            "total": len(logs),
            "logs": [l.to_dict() for l in logs],
        }), 200

    # ── Andon Cord ────────────────────────────────────────────────────────────
    @app.route("/andon/pull", methods=["POST"])
    def pull_andon():
        data = request.get_json(silent=True) or {}
        if not data.get("message"):
            abort(400, description="'message' is required")

        event = AndonEvent(message=data["message"], severity=data.get("severity", "high"))
        db.session.add(event)
        app.config["ANDON_ACTIVE"] = True

        # Report to Sentry if configured
        if SENTRY_DSN:
            sentry_sdk.capture_message(
                f"[ANDON] {data['message']}", level=data.get("severity", "error")
            )

        db.session.commit()
        return jsonify({
            "concept": "Andon Cord – stop the line to protect quality",
            "alert": event.to_dict(),
            "system_halted": True,
        }), 201

    @app.route("/andon/resolve/<int:event_id>", methods=["POST"])
    def resolve_andon(event_id):
        event = db.get_or_404(AndonEvent, event_id)
        if event.resolved:
            return jsonify({"error": "Already resolved"}), 409
        event.resolved    = True
        event.resolved_at = now_utc()
        db.session.commit()
        open_alerts = AndonEvent.query.filter_by(resolved=False).count()
        app.config["ANDON_ACTIVE"] = open_alerts > 0
        return jsonify({
            "concept": "Third Way – learn from the incident",
            "alert": event.to_dict(),
            "system_halted": app.config["ANDON_ACTIVE"],
        }), 200

    @app.route("/andon/events", methods=["GET"])
    def andon_events():
        events = AndonEvent.query.order_by(AndonEvent.raised_at.desc()).all()
        return jsonify({
            "concept": "Third Way – Continual Learning log",
            "events": [e.to_dict() for e in events],
        }), 200

    # ── Error handlers ────────────────────────────────────────────────────────
    @app.errorhandler(400)
    def bad_request(e):
        sentry_sdk.capture_exception(e)
        return jsonify({"error": "Bad request", "detail": str(e)}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        sentry_sdk.capture_exception(e)
        return jsonify({"error": "Invalid master password"}), 401

    @app.errorhandler(404)
    def not_found(e):
        sentry_sdk.capture_exception(e)
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        sentry_sdk.capture_exception(e)
        return jsonify({"error": "Method not allowed"}), 405


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", debug=False, port=5000)
    
