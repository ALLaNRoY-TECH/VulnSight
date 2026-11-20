"""VulnSight API — FastAPI application entry point."""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import config, engine, storage
from .models import MODULES, ScanRequest
from .report import to_markdown
from .scanners.target import TargetError, prepare_target

VERSION = "1.0.0"
_tasks: set[asyncio.Task] = set()
_hits: dict[str, deque] = defaultdict(deque)


@asynccontextmanager
async def lifespan(_: FastAPI):
    storage.init()
    yield


app = FastAPI(title="VulnSight API", version=VERSION, lifespan=lifespan,
              description="Web security assessment: headers, TLS, ports, exposure and DNS checks.")
app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_methods=["*"],
                   allow_headers=["*"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    # Practise what we preach.
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if request.url.path in ("/docs", "/redoc"):
        return resp  # Swagger / ReDoc load their assets from a CDN
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; object-src 'none'")
    return resp


def _rate_limit(ip: str) -> None:
    q = _hits[ip]
    now = time.monotonic()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= config.RATE_LIMIT_PER_MIN:
        raise HTTPException(429, f"Rate limit: max {config.RATE_LIMIT_PER_MIN} scans per minute.")
    q.append(now)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": VERSION, "modules": list(MODULES), "active_scans": len(engine.ACTIVE)}


@app.get("/api/modules")
async def modules():
    return [{"id": m, "label": engine.MODULE_LABELS[m]} for m in MODULES]


@app.post("/api/scans", status_code=202)
async def create_scan(req: ScanRequest, request: Request):
    if not req.authorized:
        raise HTTPException(400, "You must confirm you are authorised to scan this target.")
    try:
        await prepare_target(req.target)  # validates, resolves and applies the SSRF guard up front
    except TargetError as exc:
        raise HTTPException(422, str(exc))
    _rate_limit(request.client.host if request.client else "unknown")
    scan = engine.new_scan(req)
    task = asyncio.create_task(engine.run_scan(scan))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return {"id": scan["id"], "status": scan["status"]}


@app.get("/api/scans")
async def list_scans(limit: int = 50):
    active = [{k: s[k] for k in ("id", "target", "host", "status", "created_at", "finished_at", "score",
                                  "grade", "counts")} for s in engine.ACTIVE.values()]
    stored = [s for s in storage.list_scans(min(limit, 200)) if s["id"] not in engine.ACTIVE]
    return active + stored


@app.get("/api/stats")
async def stats():
    return storage.stats()


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = engine.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    if scan_id in engine.ACTIVE:
        raise HTTPException(409, "Scan is still running")
    if not storage.delete(scan_id):
        raise HTTPException(404, "Scan not found")
    return {"deleted": scan_id}


@app.get("/api/scans/{scan_id}/report.md", response_class=PlainTextResponse)
async def report_md(scan_id: str):
    scan = engine.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    name = f"vulnsight-{scan.get('host') or 'report'}-{scan_id}.md"
    return PlainTextResponse(to_markdown(scan), media_type="text/markdown; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/scans/{scan_id}/report.json")
async def report_json(scan_id: str):
    scan = engine.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return JSONResponse(scan, headers={
        "Content-Disposition": f'attachment; filename="vulnsight-{scan.get("host") or "report"}-{scan_id}.json"'})


# ---- Serve the built React app (single-container deployment) -------------
if config.FRONTEND_DIST.is_dir():
    assets = config.FRONTEND_DIST / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    async def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404)
        file = (config.FRONTEND_DIST / path).resolve()
        if path and file.is_file() and config.FRONTEND_DIST.resolve() in file.parents:
            return FileResponse(file)
        return FileResponse(config.FRONTEND_DIST / "index.html")
