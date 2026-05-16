"""Tests de la Task API."""

import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    with app.test_client() as c:
        yield c


# ── Endpoints generales ───────────────────────────────────────────────────────


def test_index(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.get_json()["api"] == "Task API"


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_metrics_empty(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    data = r.get_json()
    assert data["total"] == 0
    assert data["done"] == 0
    assert data["pending"] == 0


# ── CRUD de tasks ─────────────────────────────────────────────────────────────


def test_list_tasks_empty(client):
    r = client.get("/tasks")
    assert r.status_code == 200
    assert r.get_json() == []


def test_create_task(client):
    r = client.post("/tasks", json={"title": "Estudiar DevOps"})
    assert r.status_code == 201
    body = r.get_json()
    assert body["title"] == "Estudiar DevOps"
    assert body["done"] is False
    assert "id" in body
    assert "created_at" in body


def test_create_task_without_title_fails(client):
    r = client.post("/tasks", json={})
    assert r.status_code == 400


def test_create_task_with_empty_title_fails(client):
    r = client.post("/tasks", json={"title": "   "})
    assert r.status_code == 400


def test_get_task(client):
    created = client.post("/tasks", json={"title": "Tarea X"}).get_json()
    r = client.get(f"/tasks/{created['id']}")
    assert r.status_code == 200
    assert r.get_json()["title"] == "Tarea X"


def test_get_nonexistent_task(client):
    r = client.get("/tasks/999")
    assert r.status_code == 404


def test_update_task(client):
    created = client.post("/tasks", json={"title": "v1"}).get_json()
    r = client.patch(f"/tasks/{created['id']}", json={"title": "v2", "done": True})
    assert r.status_code == 200
    body = r.get_json()
    assert body["title"] == "v2"
    assert body["done"] is True


def test_update_nonexistent_task(client):
    r = client.patch("/tasks/999", json={"done": True})
    assert r.status_code == 404


def test_delete_task(client):
    created = client.post("/tasks", json={"title": "borrar"}).get_json()
    r = client.delete(f"/tasks/{created['id']}")
    assert r.status_code == 200
    # ya no existe
    assert client.get(f"/tasks/{created['id']}").status_code == 404


def test_delete_nonexistent_task(client):
    r = client.delete("/tasks/999")
    assert r.status_code == 404


# ── Métricas con datos ────────────────────────────────────────────────────────


def test_metrics_with_tasks(client):
    client.post("/tasks", json={"title": "a"})
    t2 = client.post("/tasks", json={"title": "b"}).get_json()
    client.patch(f"/tasks/{t2['id']}", json={"done": True})

    r = client.get("/metrics")
    data = r.get_json()
    assert data["total"] == 2
    assert data["done"] == 1
    assert data["pending"] == 1
    assert data["completion_pct"] == 50.0
