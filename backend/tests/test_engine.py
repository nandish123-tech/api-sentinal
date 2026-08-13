"""
tests/test_engine.py – Pytest suite for API Sentinel detection engine.

Tests run against the real in-process components with an isolated in-memory DB.
"""

from __future__ import annotations

import asyncio
import os
import pytest
import pytest_asyncio

# Point to an in-memory SQLite so tests don't touch the real DB
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

from config import settings
from inventory import normalize_route, extract_object_info, inventory_manager
from models import EndpointStatus
from ownership import OwnershipMap
from store import init_db


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_db():
    await init_db()


@pytest.fixture()
def omap() -> OwnershipMap:
    m = OwnershipMap()
    m.register("order",   "101", "user_101")
    m.register("order",   "202", "user_202")
    m.register("billing", "101", "user_101")
    m.register("billing", "202", "user_202")
    return m


# ══════════════════════════════════════════════════════════════════════════════
# Route Normalisation
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("path,expected", [
    ("/api/orders/4821",                      "/api/orders/{id}"),
    ("/api/users/202/profile",                "/api/users/{id}/profile"),
    ("/api/billing/101",                      "/api/billing/{id}"),
    ("/api/orders/4821?foo=bar",              "/api/orders/{id}"),
    ("/api/orders/",                          "/api/orders"),
    ("/api/admin/debug",                      "/api/admin/debug"),
    ("/api/items/abc-1234-xyz/details",       "/api/items/abc-1234-xyz/details"),
])
def test_normalize_route(path: str, expected: str):
    assert normalize_route(path) == expected


# ══════════════════════════════════════════════════════════════════════════════
# Object Info Extraction
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("path,obj_type,obj_id", [
    ("/api/orders/101",    "order",   "101"),
    ("/api/billing/202",   "billing", "202"),
    ("/api/users/303",     "user",    "303"),
    ("/api/admin/debug",   "",        ""),
    ("/api/products",      "",        ""),
])
def test_extract_object_info(path: str, obj_type: str, obj_id: str):
    t, i = extract_object_info(path)
    assert t == obj_type
    assert i == obj_id


# ══════════════════════════════════════════════════════════════════════════════
# Ownership Map
# ══════════════════════════════════════════════════════════════════════════════

def test_ownership_is_owner_true(omap: OwnershipMap):
    assert omap.is_owner("user_101", "order", "101") is True


def test_ownership_is_owner_false_wrong_user(omap: OwnershipMap):
    assert omap.is_owner("user_101", "order", "202") is False


def test_ownership_is_owner_unknown_object(omap: OwnershipMap):
    # Unknown object → treat as not owned
    assert omap.is_owner("user_101", "order", "999") is False


def test_ownership_get_owner(omap: OwnershipMap):
    assert omap.get_owner("billing", "202") == "user_202"


def test_ownership_register_runtime(omap: OwnershipMap):
    omap.register("order", "500", "user_500")
    assert omap.is_owner("user_500", "order", "500") is True


# ══════════════════════════════════════════════════════════════════════════════
# Inventory Manager
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_inventory_known_route():
    """A route that's in the contract should be classified as KNOWN."""
    from pathlib import Path
    contract = Path(__file__).parent.parent / "openapi_contract.yaml"
    if contract.exists():
        inventory_manager.load_contract(contract)
    status = await inventory_manager.observe("GET", "/api/orders/{id}")
    assert status == EndpointStatus.KNOWN


@pytest.mark.asyncio
async def test_inventory_shadow_api():
    """Admin debug route not in contract → UNDOCUMENTED."""
    status = await inventory_manager.observe("GET", "/api/admin/debug")
    assert status == EndpointStatus.UNDOCUMENTED


@pytest.mark.asyncio
async def test_inventory_deprecated():
    """Deprecated route in contract but marked deprecated → DEPRECATED."""
    status = await inventory_manager.observe("GET", "/api/v1/legacy/orders")
    assert status == EndpointStatus.DEPRECATED


# ══════════════════════════════════════════════════════════════════════════════
# Detection Engine Integration
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_legitimate_access_allow():
    """Owner accessing their own object → ALLOW, no alerts."""
    from engine import DetectionEngine
    from models import ApiEvent

    # Ensure ownership is seeded
    from ownership import ownership_map as om
    om.register("order", "101", "user_101")

    engine = DetectionEngine()
    event = ApiEvent(
        principal_id="user_101",
        method="GET",
        path="/api/orders/101",
        route_template="/api/orders/{id}",
        object_type="order",
        object_id="101",
    )
    result = await engine.process_event_sync(event)
    assert result.decision.value in ("ALLOW", "ALERT")  # should not BLOCK for own object
    assert "ownership_mismatch" not in result.signals


@pytest.mark.asyncio
async def test_bola_detection_blocks():
    """user_101 accessing order owned by user_202 → signals ownership_mismatch + BLOCK."""
    from engine import DetectionEngine
    from models import ApiEvent, Decision

    from ownership import ownership_map as om
    om.register("order", "202", "user_202")

    engine = DetectionEngine()
    # Lower threshold so ownership_mismatch (50 pts) triggers BLOCK
    old_threshold = settings.anomaly_score_threshold
    old_enforce   = settings.enforcement_mode
    settings.anomaly_score_threshold = 40.0
    settings.enforcement_mode = True

    event = ApiEvent(
        principal_id="user_101",
        method="GET",
        path="/api/orders/202",
        route_template="/api/orders/{id}",
        object_type="order",
        object_id="202",
    )
    result = await engine.process_event_sync(event)
    assert "ownership_mismatch" in result.signals
    assert result.decision == Decision.BLOCK

    settings.anomaly_score_threshold = old_threshold
    settings.enforcement_mode        = old_enforce


@pytest.mark.asyncio
async def test_shadow_api_detection():
    """Request to undocumented admin debug route → endpoint_novelty signal."""
    from engine import DetectionEngine
    from models import ApiEvent

    engine = DetectionEngine()
    event = ApiEvent(
        principal_id="user_101",
        method="GET",
        path="/api/admin/debug",
        route_template="/api/admin/debug",
        object_type="",
        object_id="",
    )
    result = await engine.process_event_sync(event)
    assert "endpoint_novelty" in result.signals
    assert result.risk_score > 0


@pytest.mark.asyncio
async def test_risk_score_zero_for_normal_request():
    """Public product listing → no signals, zero risk."""
    from engine import DetectionEngine
    from models import ApiEvent

    from pathlib import Path
    contract = Path(__file__).parent.parent / "openapi_contract.yaml"
    if contract.exists():
        inventory_manager.load_contract(contract)

    engine = DetectionEngine()
    event = ApiEvent(
        principal_id="anonymous",
        method="GET",
        path="/api/products",
        route_template="/api/products",
        object_type="",
        object_id="",
    )
    result = await engine.process_event_sync(event)
    assert result.risk_score == 0.0
    assert result.signals == []
