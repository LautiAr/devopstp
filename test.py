"""
test_app.py – Pytest suite for the Password Manager API

Run all (passing) tests:
    pytest test_app.py -m "not failing" -v

Run intentional failures only (for Sentry):
    pytest test_app.py -m failing -v
"""

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app import db as _db

# ── Fixtures ──────────────────────────────────────────────────────────────────

MASTER = "contraseña"
FERNET_KEY = Fernet.generate_key()


@pytest.fixture(scope="function")
def app():
    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "ANDON_ACTIVE": False,
            "FERNET_KEY": FERNET_KEY,
        }
    )
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def vault(client):
    r = client.post(
        "/vaults",
        json={
            "name": "Personal",
            "owner": "lau",
            "master_password": MASTER,
        },
    )
    assert r.status_code == 201
    return r.get_json()


@pytest.fixture
def entry(client, vault):
    r = client.post(
        f"/vaults/{vault['id']}/entries",
        json={
            "service": "github.com",
            "username": "lau",
            "password": "G!tHub$ecure99!!",
        },
        headers={"X-Master-Password": MASTER},
    )
    assert r.status_code == 201
    return r.get_json()


# ── 1. Index ──────────────────────────────────────────────────────────────────


def test_index_returns_200(client):
    r = client.get("/")
    assert r.status_code == 200


# ── 2. Vault CRUD ─────────────────────────────────────────────────────────────


class TestVaults:
    def test_create_vault(self, client):
        r = client.post(
            "/vaults", json={"name": "Work", "owner": "lau", "master_password": MASTER}
        )
        assert r.status_code == 201
        d = r.get_json()
        assert d["name"] == "Work"
        assert d["owner"] == "lau"
        assert "master_hash" not in d

    def test_create_vault_missing_name(self, client):
        r = client.post("/vaults", json={"owner": "lau", "master_password": MASTER})
        assert r.status_code == 400

    def test_create_vault_missing_master(self, client):
        r = client.post("/vaults", json={"name": "X", "owner": "lau"})
        assert r.status_code == 400

    def test_get_vault_correct_master(self, client, vault):
        r = client.get(f"/vaults/{vault['id']}", headers={"X-Master-Password": MASTER})
        assert r.status_code == 200
        assert "entradas" in r.get_json()

    def test_get_vault_wrong_master(self, client, vault):
        r = client.get(
            f"/vaults/{vault['id']}", headers={"X-Master-Password": "wrongpass"}
        )
        assert r.status_code == 401

    def test_get_vault_not_found(self, client):
        r = client.get("/vaults/9999", headers={"X-Master-Password": MASTER})
        assert r.status_code == 404

    def test_delete_vault(self, client, vault):
        r = client.delete(
            f"/vaults/{vault['id']}", headers={"X-Master-Password": MASTER}
        )
        assert r.status_code == 200
        r2 = client.get(f"/vaults/{vault['id']}", headers={"X-Master-Password": MASTER})
        assert r2.status_code == 404

    def test_delete_vault_wrong_master(self, client, vault):
        r = client.delete(
            f"/vaults/{vault['id']}", headers={"X-Master-Password": "bad"}
        )
        assert r.status_code == 401


# ── 3. Entry CRUD ─────────────────────────────────────────────────────────────


class TestEntries:
    def test_create_entry(self, client, vault):
        r = client.post(
            f"/vaults/{vault['id']}/entries",
            json={
                "service": "google.com",
                "username": "lau@g.com",
                "password": "G00gle$ecure99!!",
            },
            headers={"X-Master-Password": MASTER},
        )
        assert r.status_code == 201
        d = r.get_json()
        assert d["service"] == "google.com"
        assert "encrypted_pass" not in d

    def test_create_entry_missing_password(self, client, vault):
        r = client.post(
            f"/vaults/{vault['id']}/entries",
            json={"service": "x.com", "username": "u"},
            headers={"X-Master-Password": MASTER},
        )
        assert r.status_code == 400

    def test_create_entry_wrong_master(self, client, vault):
        r = client.post(
            f"/vaults/{vault['id']}/entries",
            json={"service": "x.com", "username": "u", "password": "P@ss99wOrd!!"},
            headers={"X-Master-Password": "bad"},
        )
        assert r.status_code == 401

    def test_list_entries(self, client, vault, entry):
        r = client.get(
            f"/vaults/{vault['id']}/entries", headers={"X-Master-Password": MASTER}
        )
        assert r.status_code == 200
        assert len(r.get_json()) >= 1

    def test_get_entry_without_reveal(self, client, vault, entry):
        r = client.get(
            f"/vaults/{vault['id']}/entries/{entry['id']}",
            headers={"X-Master-Password": MASTER},
        )
        assert r.status_code == 200
        assert "password" not in r.get_json()

    def test_get_entry_with_reveal(self, client, vault, entry):
        r = client.get(
            f"/vaults/{vault['id']}/entries/{entry['id']}?reveal=true",
            headers={"X-Master-Password": MASTER},
        )
        assert r.status_code == 200
        assert r.get_json()["password"] == "G!tHub$ecure99!!"

    def test_update_entry(self, client, vault, entry):
        r = client.patch(
            f"/vaults/{vault['id']}/entries/{entry['id']}",
            json={"notes": "Updated note"},
            headers={"X-Master-Password": MASTER},
        )
        assert r.status_code == 200
        assert r.get_json()["notes"] == "Updated note"

    def test_update_entry_password_re_encrypts(self, client, vault, entry):
        new_pwd = "NewStr0ng$Pass!!"
        client.patch(
            f"/vaults/{vault['id']}/entries/{entry['id']}",
            json={"password": new_pwd},
            headers={"X-Master-Password": MASTER},
        )
        r = client.get(
            f"/vaults/{vault['id']}/entries/{entry['id']}?reveal=true",
            headers={"X-Master-Password": MASTER},
        )
        assert r.get_json()["password"] == new_pwd

    def test_delete_entry(self, client, vault, entry):
        r = client.delete(
            f"/vaults/{vault['id']}/entries/{entry['id']}",
            headers={"X-Master-Password": MASTER},
        )
        assert r.status_code == 200
        r2 = client.get(
            f"/vaults/{vault['id']}/entries/{entry['id']}",
            headers={"X-Master-Password": MASTER},
        )
        assert r2.status_code == 404

    def test_entry_belongs_to_vault(self, client, vault):
        vault_b = client.post(
            "/vaults", json={"name": "B", "owner": "other", "master_password": MASTER}
        ).get_json()
        e = client.post(
            f"/vaults/{vault['id']}/entries",
            json={"service": "s", "username": "u", "password": "P@ssw0rd1234!!"},
            headers={"X-Master-Password": MASTER},
        ).get_json()
        r = client.get(
            f"/vaults/{vault_b['id']}/entries/{e['id']}",
            headers={"X-Master-Password": MASTER},
        )
        assert r.status_code == 404


# ── 4. Password generation & strength ────────────────────────────────────────


class TestPasswordTools:
    def test_generate_returns_strong_password(self, client):
        r = client.post("/generate", json={})
        assert r.status_code == 200
        d = r.get_json()
        assert d["fortaleza"]["strong"] is True
        assert d["puntaje"] >= 4

    def test_generate_respects_length(self, client):
        r = client.post("/generate", json={"length": 32})
        assert r.get_json()["longitud"] == 32

    def test_generate_minimum_length_enforced(self, client):
        r = client.post("/generate", json={"length": 4})
        assert r.get_json()["longitud"] >= 12

    def test_check_strength_strong(self, client):
        r = client.post("/check-strength", json={"password": "Str0ng!P@ssw0rd99"})
        assert r.status_code == 200
        assert r.get_json()["strong"] is True

    def test_check_strength_weak(self, client):
        r = client.post("/check-strength", json={"password": "password"})
        assert r.status_code == 200
        d = r.get_json()
        assert d["strong"] is False
        assert len(d["issues"]) > 0

    def test_check_strength_missing_password(self, client):
        r = client.post("/check-strength", json={})
        assert r.status_code == 400

    def test_check_strength_short_password(self, client):
        r = client.post("/check-strength", json={"password": "Ab1!"})
        d = r.get_json()
        assert d["strong"] is False
        assert any("12 caracteres" in i for i in d["issues"])


# ── 5. Lean – weak password detection ────────────────────────────────────────


class TestLean:
    def _add_entry(self, client, vault_id, password, service="svc"):
        return client.post(
            f"/vaults/{vault_id}/entries",
            json={"service": service, "username": "u", "password": password},
            headers={"X-Master-Password": MASTER},
        )

    def test_weak_password_stored_with_low_score(self, client, vault):
        r = self._add_entry(client, vault["id"], "password123")
        assert r.status_code == 201
        assert r.get_json()["strength_score"] < 3

    def test_strong_password_stored_with_high_score(self, client, vault):
        r = self._add_entry(client, vault["id"], "V3ryStr0ng!P@ss")
        assert r.get_json()["strength_score"] >= 3

    def test_metrics_reports_weak_as_waste(self, client, vault):
        self._add_entry(client, vault["id"], "weak", "svc1")
        self._add_entry(client, vault["id"], "V3ryStr0ng!P@ss99", "svc2")
        r = client.get("/metrics")
        lean = r.get_json()["lean"]
        assert lean["entradas_debiles"] >= 1
        assert lean["desperdicio_pct"] > 0


# ── 6. Andon Cord ─────────────────────────────────────────────────────────────


class TestAndon:
    def test_pull_cord(self, client):
        r = client.post(
            "/andon/pull",
            json={"message": "Prueba Andon Cord", "severity": "high"},
        )
        assert r.status_code == 201
        assert r.get_json()["sistema_detenido"] is True

    def test_cord_halts_writes(self, client):
        client.post("/andon/pull", json={"message": "Detener"})
        r = client.post(
            "/vaults", json={"name": "X", "owner": "y", "master_password": MASTER}
        )
        assert r.status_code == 503

    def test_cord_allows_reads(self, client):
        client.post("/andon/pull", json={"message": "Detener"})
        assert client.get("/metrics").status_code == 200
        assert client.get("/andon/events").status_code == 200

    def test_resolve_cord(self, client):
        pull = client.post("/andon/pull", json={"message": "Issue"}).get_json()
        r = client.post(f"/andon/resolve/{pull['alerta']['id']}")
        assert r.status_code == 200
        assert r.get_json()["sistema_detenido"] is False

    def test_resolve_already_resolved(self, client):
        pull = client.post("/andon/pull", json={"message": "X"}).get_json()
        client.post(f"/andon/resolve/{pull['alerta']['id']}")
        r = client.post(f"/andon/resolve/{pull['alerta']['id']}")
        assert r.status_code == 409

    def test_multiple_alerts_all_must_resolve(self, client):
        a = client.post("/andon/pull", json={"message": "A"}).get_json()
        b = client.post("/andon/pull", json={"message": "B"}).get_json()
        client.post(f"/andon/resolve/{a['alerta']['id']}")
        r = client.post(
            "/vaults", json={"name": "X", "owner": "y", "master_password": MASTER}
        )
        assert r.status_code == 503
        client.post(f"/andon/resolve/{b['alerta']['id']}")
        r = client.post(
            "/vaults", json={"name": "X", "owner": "y", "master_password": MASTER}
        )
        assert r.status_code == 201

    def test_pull_requires_message(self, client):
        r = client.post("/andon/pull", json={})
        assert r.status_code == 400

    def test_list_andon_events(self, client):
        client.post("/andon/pull", json={"message": "A"})
        client.post("/andon/pull", json={"message": "B"})
        r = client.get("/andon/events")
        assert r.status_code == 200
        assert len(r.get_json()["eventos"]) == 2


# ── 7. Metrics & Audit ────────────────────────────────────────────────────────


class TestMetricsAndAudit:
    def test_metrics_structure(self, client):
        r = client.get("/metrics")
        assert r.status_code == 200
        m = r.get_json()
        for key in ("vaults", "entradas", "lean", "seguridad", "actividad_reciente"):
            assert key in m

    def test_metrics_vault_count(self, client, vault):
        r = client.get("/metrics")
        assert r.get_json()["vaults"] >= 1

    def test_audit_log_records_vault_creation(self, client, vault):
        r = client.get("/audit")
        assert r.status_code == 200
        logs = r.get_json()["logs"]
        actions = [l["action"] for l in logs]
        assert "vault_created" in actions

    def test_audit_log_records_entry_access(self, client, vault, entry):
        client.get(
            f"/vaults/{vault['id']}/entries/{entry['id']}",
            headers={"X-Master-Password": MASTER},
        )
        logs = client.get("/audit").get_json()["logs"]
        assert any(l["action"] == "entry_accessed" for l in logs)

    def test_audit_log_records_denied_access(self, client, vault):
        client.get(f"/vaults/{vault['id']}", headers={"X-Master-Password": "wrong"})
        logs = client.get("/audit").get_json()["logs"]
        assert any(l["action"] == "vault_access_denied" for l in logs)


# ── 8. Error handlers ─────────────────────────────────────────────────────────


class TestErrors:
    def test_404_is_json(self, client):
        r = client.get("/nonexistent")
        assert r.status_code == 404
        assert r.get_json() is not None

    def test_405_is_json(self, client):
        r = client.delete("/vaults")
        assert r.status_code == 405
        assert r.get_json() is not None


# ═══════════════════════════════════════════════════════════════════════════════
# INTENTIONAL FAILURES (run with -m failing to demo Sentry dashboard)
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.failing
class TestIntentionalFailures:
    def test_FAIL_weak_password_should_be_rejected_but_is_not(self, client, vault):
        r = client.post(
            f"/vaults/{vault['id']}/entries",
            json={"service": "legacy.com", "username": "u", "password": "123"},
            headers={"X-Master-Password": MASTER},
        )
        assert r.status_code == 422

    def test_FAIL_duplicate_service_in_vault_should_be_prevented(self, client, vault):
        payload = {
            "service": "dup.com",
            "username": "u",
            "password": "Str0ng!P@ss99",
            "notes": "",
        }
        client.post(
            f"/vaults/{vault['id']}/entries",
            json=payload,
            headers={"X-Master-Password": MASTER},
        )
        r = client.post(
            f"/vaults/{vault['id']}/entries",
            json=payload,
            headers={"X-Master-Password": MASTER},
        )
        assert r.status_code == 409

    def test_FAIL_generate_always_returns_unique_passwords(self, client):
        passwords = {
            client.post("/generate", json={"length": 12}).get_json()["password"]
            for _ in range(50)
        }
        assert len(passwords) < 50

    def test_FAIL_metrics_entry_total_matches_sum_of_strength_buckets(
        self, client, vault
    ):
        for i in range(3):
            client.post(
                f"/vaults/{vault['id']}/entries",
                json={
                    "service": f"s{i}",
                    "username": "u",
                    "password": f"Str0ng!P@ss{i}9!!",
                },
                headers={"X-Master-Password": MASTER},
            )

        m = client.get("/metrics").get_json()
        total = m["entradas"]["total"]
        bucket_sum = sum(m["entradas"]["por_fortaleza"].values())
        assert total != bucket_sum

    def test_FAIL_vault_deletion_cascades_to_audit_log(self, client, vault):
        client.post(
            f"/vaults/{vault['id']}/entries",
            json={"service": "s", "username": "u", "password": "P@ssw0rd99!!"},
            headers={"X-Master-Password": MASTER},
        )
        client.delete(f"/vaults/{vault['id']}", headers={"X-Master-Password": MASTER})

        logs = client.get("/audit").get_json()["logs"]
        vault_logs = [l for l in logs if l["vault_id"] == vault["id"]]
        assert len(vault_logs) == 0
