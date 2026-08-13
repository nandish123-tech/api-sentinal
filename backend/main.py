"""
main.py – API Sentinel application entry point.

Startup sequence:
  1. Initialise the SQLite database
  2. Load the declared OpenAPI contract
  3. Seed the ownership map
  4. Start the detection engine background listener
  5. Mount the Sentinel middleware
  6. Register all routers
  7. Serve the dashboard as a static file
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from config import settings
from engine import detection_engine
from inventory import inventory_manager
from middleware import SentinelMiddleware
from ownership import ownership_map
from routers.dashboard import router as dashboard_router
from routers.sandbox import router as sandbox_router
from store import init_db


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Init DB
    await init_db()

    # 2. Load OpenAPI contract
    contract_path = Path(__file__).parent / settings.openapi_contract_path
    count = inventory_manager.load_contract(contract_path)
    print(f"[sentinel] Loaded {count} routes from declared contract: {contract_path.name}")

    # 3. Seed ownership map
    seed_path = Path(__file__).parent / "data" / "ownership_seed.json"
    ownership_map.load_from_file(seed_path)
    print(f"[sentinel] Ownership map seeded from {seed_path.name}")

    # 4. Start detection engine background loop
    await detection_engine.start()
    print("[sentinel] Detection engine started [OK]")

    print("[sentinel] API Sentinel is LIVE - http://localhost:8000")
    yield

    print("[sentinel] Shutting down.")


# ── Application ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="API Sentinel",
    version="1.0.0",
    description=(
        "Runtime API security — live inventory tracking, "
        "BOLA detection, and Shadow API discovery."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Sentinel middleware (must be added AFTER CORS) ────────────────────────────
app.add_middleware(SentinelMiddleware)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(dashboard_router)
app.include_router(sandbox_router)


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["system"])
async def health():
    return {
        "status": "ok",
        "version": app.version,
        "enforcement": settings.enforcement_mode,
        "declared_routes": inventory_manager.declared_count,
    }


# ── Dashboard (serve frontend/index.html at root) ─────────────────────────────
_frontend = Path(__file__).parent.parent / "frontend"

if _frontend.exists():
    app.mount("/static", StaticFiles(directory=str(_frontend)), name="static")

    @app.get("/", include_in_schema=False)
    async def dashboard():
        return FileResponse(str(_frontend / "index.html"))
