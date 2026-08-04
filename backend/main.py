"""
Ephemeral Enhancement — run tracker API and dashboard.

Run locally with:

    cd backend
    cp .env.example .env        # set EE_TOKEN
    pip install -r requirements.txt
    uvicorn main:app --reload

Clients join with ``run_pipeline.py --join-network <token>``.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

import db

load_dotenv()

BASE_DIR = Path(__file__).parent
TOKENS = {
    t.strip() for t in os.getenv("EE_TOKEN", "").split(",") if t.strip()
}
GITHUB_REPO = os.getenv("EE_GITHUB_REPO", "landoncrabtree/ephemeral-enhancement")
GITHUB_BRANCH = os.getenv("EE_GITHUB_BRANCH", "main")

app = FastAPI(title="Ephemeral Enhancement Tracker", docs_url="/api/docs")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.on_event("startup")
def _startup() -> None:
    db.init_db()
    if not TOKENS:
        print("[warn] EE_TOKEN is empty — all write requests will be rejected.")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def require_token(authorization: str = Header(default="")) -> str:
    """Validate the ``Authorization: Bearer <token>`` header for writes."""
    if not TOKENS:
        raise HTTPException(503, "Server has no EE_TOKEN configured")
    token = authorization.removeprefix("Bearer ").strip()
    if token not in TOKENS:
        raise HTTPException(401, "Invalid or missing token")
    return token


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RunSubmission(BaseModel):
    """One completed (or aborted) pipeline execution."""

    fingerprint: str = Field(min_length=8, max_length=128)
    pipeline: str
    ciphertext: str
    ciphertext_sha: str
    ciphertext_label: str | None = None
    dictionary: str | None = None
    dictionary_sha: str | None = None
    n_keys: int | None = None
    axes: list[tuple[str, int]] = []
    combos: int = 0
    hits: int = 0
    best_score: float | None = None
    best_plaintext: str | None = None
    best_meta: dict[str, Any] | None = None
    threshold: float | None = None
    vary_case: bool = False
    status: str = "complete"
    semantics_version: int | None = None
    git_commit: str | None = None
    runner: str | None = None
    duration_s: float | None = None


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.get("/api/runs/{fingerprint}")
def api_get_run(fingerprint: str) -> dict[str, Any]:
    """Has this exact search space already been run? Used by the client to skip."""
    run = db.get_run(fingerprint)
    if run is None:
        return {"found": False}
    return {"found": True, "run": run}


@app.post("/api/runs", status_code=201)
def api_post_run(
    sub: RunSubmission, _: str = Depends(require_token)
) -> dict[str, Any]:
    """Record a run. Replaces a stored run only if the new one is better."""
    payload = sub.model_dump()
    payload["axes_json"] = json.dumps(sub.axes)
    payload["best_meta_json"] = (
        json.dumps(sub.best_meta) if sub.best_meta else None
    )
    payload["vary_case"] = int(sub.vary_case)
    created, row = db.upsert_run(payload)
    return {"created": created, "run": row}


@app.get("/api/stats")
def api_stats() -> dict[str, Any]:
    return db.stats()


_gh_cache: dict[str, Any] = {"at": 0.0, "data": None}


@app.get("/api/version")
def api_version() -> dict[str, Any]:
    """
    Latest upstream commit, so clients can warn when they are out of date.

    Uses the unauthenticated GitHub API (60 requests/hour per IP) and caches
    for 10 minutes, so many clients polling cost one upstream request.
    """
    now = time.time()
    if _gh_cache["data"] is not None and now - _gh_cache["at"] < 600:
        return _gh_cache["data"]

    url = f"https://api.github.com/repos/{GITHUB_REPO}/commits/{GITHUB_BRANCH}"
    try:
        with httpx.Client(timeout=5.0) as client:
            r = client.get(url, headers={"Accept": "application/vnd.github+json"})
            r.raise_for_status()
            j = r.json()
        data = {
            "repo": GITHUB_REPO,
            "branch": GITHUB_BRANCH,
            "sha": j["sha"],
            "short_sha": j["sha"][:7],
            "message": j["commit"]["message"].splitlines()[0],
            "date": j["commit"]["committer"]["date"],
            "url": j["html_url"],
        }
    except Exception as exc:  # upstream hiccup must not break clients
        data = {"repo": GITHUB_REPO, "error": str(exc)}
    _gh_cache.update(at=now, data=data)
    return data


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    q: str | None = Query(default=None),
    ct: str | None = Query(default=None),
    only_hits: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=10, le=200),
) -> HTMLResponse:
    total = db.count_runs(ciphertext_sha=ct, only_hits=only_hits, search=q)
    pages = max(1, -(-total // per_page))
    page = min(page, pages)
    runs = db.list_runs(
        limit=per_page,
        offset=(page - 1) * per_page,
        ciphertext_sha=ct,
        only_hits=only_hits,
        search=q,
    )
    for r in runs:
        r["axes"] = db.decode_axes(r.get("axes_json"))

    # Preserve active filters across page links.
    params = []
    if q:
        params.append(f"q={q}")
    if ct:
        params.append(f"ct={ct}")
    if only_hits:
        params.append("only_hits=true")
    if per_page != 50:
        params.append(f"per_page={per_page}")
    base_query = ("&" + "&".join(params)) if params else ""

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "runs": runs,
            "stats": db.stats(),
            "targets": db.ciphertext_summary(),
            "q": q or "",
            "ct": ct or "",
            "only_hits": only_hits,
            "version": api_version(),
            "page": page,
            "pages": pages,
            "total": total,
            "base_query": base_query,
        },
    )


@app.get("/run/{fingerprint}", response_class=HTMLResponse)
def run_detail(request: Request, fingerprint: str) -> HTMLResponse:
    run = db.get_run(fingerprint)
    if run is None:
        raise HTTPException(404, "No such run")
    run["axes"] = db.decode_axes(run.get("axes_json"))
    if run.get("best_meta_json"):
        try:
            run["best_meta"] = json.loads(run["best_meta_json"])
        except ValueError:
            run["best_meta"] = None
    return templates.TemplateResponse(request, "run.html", {"run": run})
