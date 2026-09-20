import hashlib
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.cqrs import list_events, start_run
from app.database import Base, get_db
from app.main import app


# JSONB not available on SQLite — compile it as JSON for tests
@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type, compiler, **kw):
    return "JSON"


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


METRIC_BODY = {"name": "loss", "value": 0.5, "step": 1}
ARTIFACT_BODY = {
    "name": "model.bin",
    "uri": "s3://lab-artifacts/model.bin",
    "content_sha256": sha("model"),
    "media_type": "application/octet-stream",
}


@pytest.fixture()
def ctx():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    run = start_run(
        session,
        actor="researcher",
        project="p1",
        name="rbac-run",
        dataset_content_sha256=sha("ds"),
        code_commit_sha="abc1234",
        description="role write policy test",
    )
    run_id = str(run.id)

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    # TestClient without context-manager entry so the Postgres-bound lifespan
    # (Base.metadata.create_all) does not run; tables exist on the SQLite engine.
    client = TestClient(app)
    try:
        yield client, session, run_id
    finally:
        app.dependency_overrides.clear()
        session.close()


def _auth(client: TestClient, username: str, password: str) -> dict:
    resp = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.fixture()
def researcher_headers(ctx):
    client, _, _ = ctx
    return _auth(client, "researcher", "lab123456")


@pytest.fixture()
def auditor_headers(ctx):
    client, _, _ = ctx
    return _auth(client, "auditor", "audit123456")


def test_auditor_cannot_record_metric(ctx, auditor_headers):
    client, session, run_id = ctx
    resp = client.post(
        f"/api/runs/{run_id}/metrics",
        json={**METRIC_BODY, "expected_version": 1},
        headers=auditor_headers,
    )
    assert resp.status_code == 403
    # denied before any event is appended
    assert len(list_events(session, UUID(run_id))) == 1


def test_auditor_cannot_attach_artifact(ctx, auditor_headers):
    client, session, run_id = ctx
    resp = client.post(
        f"/api/runs/{run_id}/artifacts",
        json={**ARTIFACT_BODY, "expected_version": 1},
        headers=auditor_headers,
    )
    assert resp.status_code == 403
    assert len(list_events(session, UUID(run_id))) == 1


def test_auditor_keeps_read_access(ctx, auditor_headers):
    client, _, run_id = ctx
    assert client.get(f"/api/runs/{run_id}", headers=auditor_headers).status_code == 200
    assert client.get(
        f"/api/runs/{run_id}/events", headers=auditor_headers
    ).status_code == 200


def test_anonymous_write_rejected(ctx):
    client, _, run_id = ctx
    assert client.post(
        f"/api/runs/{run_id}/metrics", json={**METRIC_BODY, "expected_version": 1}
    ).status_code == 401


def test_researcher_records_metric_and_attaches_artifact(ctx, researcher_headers):
    client, session, run_id = ctx

    resp = client.post(
        f"/api/runs/{run_id}/metrics",
        json={**METRIC_BODY, "expected_version": 1},
        headers=researcher_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["version"] == 2
    assert len(body["metrics_json"]) == 1
    assert body["metrics_json"][0]["name"] == "loss"

    resp = client.post(
        f"/api/runs/{run_id}/artifacts",
        json={**ARTIFACT_BODY, "expected_version": 2},
        headers=researcher_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["version"] == 3
    assert len(body["artifacts_json"]) == 1
    assert body["artifacts_json"][0]["name"] == "model.bin"
    assert body["status"] == "running"

    event_types = [e.event_type for e in list_events(session, UUID(run_id))]
    assert event_types == ["RunStarted", "MetricRecorded", "ArtifactAttached"]
