"""角色写权限：记指标与挂产物仅研究员可写，审计员只读。"""

import hashlib
import importlib.util

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import router
from app.auth import create_access_token
from app.database import Base, get_db


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # JSONB not available on SQLite — compile as JSON (same shim as test_state_machine)
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    @compiles(JSONB, "sqlite")
    def _compile_jsonb_sqlite(_type, compiler, **kw):
        return "JSON"

    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client


def auth_headers(role: str) -> dict:
    username = "researcher" if role == "researcher" else "auditor"
    token = create_access_token(username, role)
    return {"Authorization": f"Bearer {token}"}


def start_run(client: TestClient) -> dict:
    resp = client.post(
        "/api/runs",
        json={
            "project": "p1",
            "name": "n1",
            "dataset_content_sha256": sha("ds"),
            "code_commit_sha": "abc1234",
            "expected_version": 0,
        },
        headers=auth_headers("researcher"),
    )
    assert resp.status_code == 201
    return resp.json()


def metric_body() -> dict:
    return {"name": "acc", "value": 0.9, "step": 1, "expected_version": 1}


def artifact_body() -> dict:
    return {
        "name": "model.bin",
        "uri": "file:///tmp/model.bin",
        "content_sha256": sha("model"),
        "media_type": "application/octet-stream",
        "expected_version": 1,
    }


def test_auditor_cannot_record_metric(client):
    run = start_run(client)
    resp = client.post(
        f"/api/runs/{run['id']}/metrics",
        json=metric_body(),
        headers=auth_headers("auditor"),
    )
    assert resp.status_code == 403

    after = client.get(f"/api/runs/{run['id']}", headers=auth_headers("auditor")).json()
    assert after["version"] == run["version"]
    assert after["metrics_json"] == []


def test_auditor_cannot_attach_artifact(client):
    run = start_run(client)
    resp = client.post(
        f"/api/runs/{run['id']}/artifacts",
        json=artifact_body(),
        headers=auth_headers("auditor"),
    )
    assert resp.status_code == 403

    after = client.get(f"/api/runs/{run['id']}", headers=auth_headers("auditor")).json()
    assert after["version"] == run["version"]
    assert after["artifacts_json"] == []


def test_researcher_can_record_metric(client):
    run = start_run(client)
    resp = client.post(
        f"/api/runs/{run['id']}/metrics",
        json=metric_body(),
        headers=auth_headers("researcher"),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == run["version"] + 1
    assert body["metrics_json"][0]["name"] == "acc"


def test_researcher_can_attach_artifact(client):
    run = start_run(client)
    resp = client.post(
        f"/api/runs/{run['id']}/artifacts",
        json=artifact_body(),
        headers=auth_headers("researcher"),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == run["version"] + 1
    assert body["artifacts_json"][0]["name"] == "model.bin"


def test_auditor_read_endpoints_still_work(client):
    run = start_run(client)
    assert client.get(f"/api/runs/{run['id']}", headers=auth_headers("auditor")).status_code == 200
    assert client.get(f"/api/runs/{run['id']}/events", headers=auth_headers("auditor")).status_code == 200
    assert client.get(f"/api/runs/{run['id']}/lineage", headers=auth_headers("auditor")).status_code == 200


def test_auditor_write_bypass_module_removed():
    assert importlib.util.find_spec("app.AuditorWriteBypass") is None
