"""
inventory.py – Runtime API inventory manager.

Loads the declared OpenAPI contract at startup, then continuously classifies
every observed route as: known / undocumented / deprecated.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from models import EndpointStatus, InventoryEntry
from store import InventoryStore


# ── Route normalisation helpers ────────────────────────────────────────────────

_UUID_RE    = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_DIGIT_RE   = re.compile(r"(?<=/)\d+(?=/|$)")


def normalize_route(path: str) -> str:
    """
    Convert a concrete path to a route template.

    /api/orders/4821          → /api/orders/{id}
    /api/users/abc-uuid-…/…   → /api/users/{uuid}/…
    /api/billing/202          → /api/billing/{id}
    """
    # Strip query string first before any substitutions
    path = path.split("?")[0].rstrip("/")
    path = _UUID_RE.sub("{uuid}", path)
    path = _DIGIT_RE.sub("{id}", path)
    return path or "/"


def extract_object_info(path: str) -> tuple[str, str]:
    """
    Return (object_type, object_id) from a path like /api/orders/4821.
    Falls back to ("", "").
    """
    parts = [p for p in path.split("/") if p]
    # Look for pattern: …/<type>/<id>
    for i in range(len(parts) - 1):
        segment = parts[i + 1]
        if segment.isdigit() or _UUID_RE.match(segment):
            return parts[i].rstrip("s"), segment  # e.g. "order", "4821"
    return "", ""


# ══════════════════════════════════════════════════════════════════════════════
# Inventory Manager
# ══════════════════════════════════════════════════════════════════════════════

class InventoryManager:
    """
    Maintains the declared API contract (from OpenAPI YAML) and the live
    observed inventory (built from middleware events).
    """

    def __init__(self) -> None:
        # Declared routes from the OAS contract: { "GET:/api/orders/{id}" : metadata }
        self._declared: dict[str, dict[str, Any]] = {}
        self._deprecated: set[str] = set()   # keys that are marked deprecated in OAS
        self._loaded_path: str | None = None

    # ── Contract loading ──────────────────────────────────────────────────────

    def load_contract(self, path: str | Path) -> int:
        """Parse OpenAPI YAML and populate _declared. Returns # of routes loaded."""
        p = Path(path)
        if not p.exists():
            return 0
        with open(p, encoding="utf-8") as fh:
            spec: dict = yaml.safe_load(fh)
        self._declared.clear()
        self._deprecated.clear()
        self._loaded_path = str(p)

        paths: dict = spec.get("paths", {})
        for oas_path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            # OAS uses {paramName}, normalise to {id}/{uuid} for matching
            norm_path = re.sub(r"\{[^}]+\}", "{id}", oas_path)
            for method, op in methods.items():
                if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                    key = f"{method.upper()}:{norm_path}"
                    deprecated = op.get("deprecated", False) if isinstance(op, dict) else False
                    self._declared[key] = {
                        "summary": (op.get("summary", "") if isinstance(op, dict) else ""),
                        "tags":    (op.get("tags", [])    if isinstance(op, dict) else []),
                        "deprecated": deprecated,
                    }
                    if deprecated:
                        self._deprecated.add(key)
        return len(self._declared)

    @property
    def declared_count(self) -> int:
        return len(self._declared)

    # ── Observation / classification ──────────────────────────────────────────

    async def observe(self, method: str, route_template: str, risk_score: float = 0.0) -> EndpointStatus:
        """
        Record that a request was seen for (method, route_template).
        Returns the classification for this route.
        """
        key = f"{method.upper()}:{route_template}"
        declared_meta = self._declared.get(key)

        if key in self._deprecated:
            status = EndpointStatus.DEPRECATED
        elif declared_meta is not None:
            status = EndpointStatus.KNOWN
        else:
            status = EndpointStatus.UNDOCUMENTED

        # Update or create inventory entry
        existing = await InventoryStore.get(method, route_template)
        now = datetime.utcnow()

        if existing:
            new_count = existing.request_count + 1
            new_avg = (existing.risk_score_avg * existing.request_count + risk_score) / new_count
            updated = InventoryEntry(
                route_template=route_template,
                method=method.upper(),
                status=status,
                first_seen=existing.first_seen,
                last_seen=now,
                request_count=new_count,
                tags=declared_meta.get("tags", []) if declared_meta else [],
                summary=declared_meta.get("summary", "") if declared_meta else "",
                risk_score_avg=round(new_avg, 2),
            )
        else:
            updated = InventoryEntry(
                route_template=route_template,
                method=method.upper(),
                status=status,
                first_seen=now,
                last_seen=now,
                request_count=1,
                tags=declared_meta.get("tags", []) if declared_meta else [],
                summary=declared_meta.get("summary", "") if declared_meta else "",
                risk_score_avg=round(risk_score, 2),
            )

        await InventoryStore.upsert(updated)
        return status


# ── Singleton ─────────────────────────────────────────────────────────────────
inventory_manager = InventoryManager()
