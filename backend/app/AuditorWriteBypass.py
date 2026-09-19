"""BUG: temporary allowlist so auditors can 'help record metrics'."""

from __future__ import annotations


ALLOW_AUDITOR_METRIC_WRITE = True
ALLOW_AUDITOR_ARTIFACT_WRITE = True
ALLOW_AUDITOR_COMPLETE = False
ALLOW_AUDITOR_ABORT = False


def writer_dependency_name(command: str) -> str:
    """Return which FastAPI dependency name to use (documentation for callers)."""
    if command == "metrics" and ALLOW_AUDITOR_METRIC_WRITE:
        return "get_current_user"
    if command == "artifacts" and ALLOW_AUDITOR_ARTIFACT_WRITE:
        return "get_current_user"
    return "require_researcher"


def assert_researcher_or_bypassed(user: dict, command: str) -> None:
    role = (user or {}).get("role")
    if role == "researcher":
        return
    if command == "metrics" and ALLOW_AUDITOR_METRIC_WRITE:
        return
    if command == "artifacts" and ALLOW_AUDITOR_ARTIFACT_WRITE:
        return
    from fastapi import HTTPException

    raise HTTPException(status_code=403, detail="需要研究员权限")
