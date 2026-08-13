"""
ownership.py – Ownership map for BOLA detection.

Loads seed data from data/ownership_seed.json and supports runtime additions.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


class OwnershipMap:
    """
    Maps (object_type, object_id) → owner_id.

    Keys are stored as  "object_type:object_id"  strings for fast lookup.
    """

    def __init__(self) -> None:
        # { "order:101": "user_101", "billing:202": "user_202", ... }
        self._map: dict[str, str] = {}
        self._roles: dict[str, str] = {}  # key → role label

    def load_from_file(self, path: str | Path) -> None:
        seed_path = Path(path)
        if not seed_path.exists():
            return
        with open(seed_path, encoding="utf-8") as fh:
            data: list[dict] = json.load(fh)
        for entry in data:
            self._add(entry["object_type"], entry["object_id"], entry["owner_id"],
                      entry.get("role", "owner"))

    def _key(self, object_type: str, object_id: str) -> str:
        return f"{object_type.lower()}:{object_id}"

    @staticmethod
    def _normalize_principal(principal_id: str) -> str:
        """Normalize bare numeric IDs: '101' -> 'user_101'."""
        if principal_id.isdigit():
            return f"user_{principal_id}"
        return principal_id

    def _add(self, object_type: str, object_id: str, owner_id: str, role: str = "owner") -> None:
        k = self._key(object_type, object_id)
        self._map[k] = owner_id
        self._roles[k] = role

    def register(self, object_type: str, object_id: str, owner_id: str, role: str = "owner") -> None:
        """Runtime registration (e.g., when a new order is created)."""
        self._add(object_type, object_id, owner_id, role)

    def get_owner(self, object_type: str, object_id: str) -> str | None:
        return self._map.get(self._key(object_type, object_id))

    def get_role(self, object_type: str, object_id: str) -> str | None:
        return self._roles.get(self._key(object_type, object_id))

    def is_owner(self, principal_id: str, object_type: str, object_id: str) -> bool:
        owner = self.get_owner(object_type, object_id)
        if owner is None:
            # Unknown object — cannot confirm ownership; treat as suspicious
            return False
        return owner == self._normalize_principal(principal_id)

    def all_entries(self) -> list[dict]:
        result = []
        for k, owner in self._map.items():
            obj_type, obj_id = k.split(":", 1)
            result.append({
                "object_type": obj_type,
                "object_id":   obj_id,
                "owner_id":    owner,
                "role":        self._roles.get(k, "owner"),
            })
        return result


# ── Singleton ─────────────────────────────────────────────────────────────────
ownership_map = OwnershipMap()
