"""
store.py – Async SQLite-backed stores for ApiEvents and SentinelAlerts.
Uses SQLAlchemy async engine + aiosqlite driver.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, func, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from config import settings
from models import (
    ApiEventORM, SentinelAlertORM, InventoryEntryORM,
    ApiEvent, SentinelAlert, InventoryEntry,
    Base, Decision, EndpointStatus, AlertType, Severity,
)


# ── Engine + session factory ──────────────────────────────────────────────────
_engine = create_async_engine(settings.database_url, echo=False)
AsyncSessionLocal = async_sessionmaker(_engine, expire_on_commit=False)


async def init_db() -> None:
    """Create all tables (idempotent)."""
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# ══════════════════════════════════════════════════════════════════════════════
# Event Store
# ══════════════════════════════════════════════════════════════════════════════

class EventStore:
    """Persists ApiEvent records and answers sliding-window enumeration queries."""

    # Fast in-memory cache for the most recent N events
    _cache: deque[ApiEvent] = deque(maxlen=settings.max_events_in_memory)
    _lock = asyncio.Lock()

    @classmethod
    async def insert(cls, event: ApiEvent) -> None:
        async with cls._lock:
            cls._cache.appendleft(event)
        async with AsyncSessionLocal() as session:
            orm = ApiEventORM(
                id=event.id,
                timestamp=event.timestamp,
                principal_id=event.principal_id,
                method=event.method,
                path=event.path,
                route_template=event.route_template,
                object_type=event.object_type,
                object_id=event.object_id,
                status_code=event.status_code,
                latency_ms=event.latency_ms,
                declared_match=event.declared_match,
                user_agent=event.user_agent,
                client_ip=event.client_ip,
                signals=event.signals,
                risk_score=event.risk_score,
                decision=event.decision.value,
            )
            session.add(orm)
            await session.commit()

    @classmethod
    async def recent(cls, limit: int = 100) -> list[ApiEvent]:
        return list(cls._cache)[:limit]

    @classmethod
    async def count_distinct_objects(
        cls,
        principal_id: str,
        object_type: str,
        window_seconds: int,
    ) -> int:
        """Count how many distinct object IDs principal has accessed in the window."""
        cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(func.count(ApiEventORM.object_id.distinct()))
                .where(
                    and_(
                        ApiEventORM.principal_id == principal_id,
                        ApiEventORM.object_type  == object_type,
                        ApiEventORM.timestamp    >= cutoff,
                    )
                )
            )
            return result.scalar_one() or 0

    @classmethod
    async def total_count(cls) -> int:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(func.count(ApiEventORM.id)))
            return result.scalar_one() or 0

    @classmethod
    async def events_per_minute(cls) -> float:
        cutoff = datetime.utcnow() - timedelta(minutes=1)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(func.count(ApiEventORM.id))
                .where(ApiEventORM.timestamp >= cutoff)
            )
            return float(result.scalar_one() or 0)

    @classmethod
    async def blocked_count(cls) -> int:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(func.count(ApiEventORM.id))
                .where(ApiEventORM.decision == Decision.BLOCK.value)
            )
            return result.scalar_one() or 0


# ══════════════════════════════════════════════════════════════════════════════
# Alert Store
# ══════════════════════════════════════════════════════════════════════════════

class AlertStore:
    """Persists SentinelAlert records."""

    _cache: deque[SentinelAlert] = deque(maxlen=settings.max_alerts_in_memory)
    _lock = asyncio.Lock()

    @classmethod
    async def insert(cls, alert: SentinelAlert) -> None:
        async with cls._lock:
            cls._cache.appendleft(alert)
        async with AsyncSessionLocal() as session:
            orm = SentinelAlertORM(
                id=alert.id,
                timestamp=alert.timestamp,
                alert_type=alert.alert_type.value,
                severity=alert.severity.value,
                principal_id=alert.principal_id,
                method=alert.method,
                route_template=alert.route_template,
                object_type=alert.object_type,
                object_id=alert.object_id,
                expected_owner=alert.expected_owner,
                signals=alert.signals,
                evidence=alert.evidence,
                risk_score=alert.risk_score,
                decision=alert.decision.value,
                resolved=alert.resolved,
                notes=alert.notes,
            )
            session.add(orm)
            await session.commit()

    @classmethod
    async def recent(cls, limit: int = 100, alert_type: str | None = None) -> list[SentinelAlert]:
        alerts = list(cls._cache)
        if alert_type:
            alerts = [a for a in alerts if a.alert_type.value == alert_type]
        return alerts[:limit]

    @classmethod
    async def total_count(cls) -> int:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(func.count(SentinelAlertORM.id)))
            return result.scalar_one() or 0

    @classmethod
    async def count_by_type(cls) -> dict[str, int]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(SentinelAlertORM.alert_type, func.count(SentinelAlertORM.id))
                .group_by(SentinelAlertORM.alert_type)
            )
            return {row[0]: row[1] for row in result.all()}

    @classmethod
    async def count_by_severity(cls) -> dict[str, int]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(SentinelAlertORM.severity, func.count(SentinelAlertORM.id))
                .group_by(SentinelAlertORM.severity)
            )
            return {row[0]: row[1] for row in result.all()}


# ══════════════════════════════════════════════════════════════════════════════
# Inventory Store
# ══════════════════════════════════════════════════════════════════════════════

class InventoryStore:
    """Persists InventoryEntry records."""

    _cache: dict[str, InventoryEntry] = {}  # key = "METHOD:route_template"
    _lock = asyncio.Lock()

    @classmethod
    def _key(cls, method: str, route_template: str) -> str:
        return f"{method.upper()}:{route_template}"

    @classmethod
    async def upsert(cls, entry: InventoryEntry) -> None:
        k = cls._key(entry.method, entry.route_template)
        async with cls._lock:
            cls._cache[k] = entry
        async with AsyncSessionLocal() as session:
            existing = await session.get(InventoryEntryORM, (entry.route_template, entry.method.upper()))
            if existing:
                existing.last_seen = entry.last_seen
                existing.request_count = entry.request_count
                existing.status = entry.status.value
                existing.risk_score_avg = entry.risk_score_avg
            else:
                session.add(InventoryEntryORM(
                    route_template=entry.route_template,
                    method=entry.method.upper(),
                    status=entry.status.value,
                    first_seen=entry.first_seen,
                    last_seen=entry.last_seen,
                    request_count=entry.request_count,
                    tags=entry.tags,
                    summary=entry.summary,
                    risk_score_avg=entry.risk_score_avg,
                ))
            await session.commit()

    @classmethod
    async def all(cls) -> list[InventoryEntry]:
        return list(cls._cache.values())

    @classmethod
    async def get(cls, method: str, route_template: str) -> InventoryEntry | None:
        return cls._cache.get(cls._key(method, route_template))

    @classmethod
    async def shadow_count(cls) -> int:
        return sum(1 for e in cls._cache.values() if e.status == EndpointStatus.UNDOCUMENTED)

    @classmethod
    async def deprecated_active_count(cls) -> int:
        return sum(1 for e in cls._cache.values() if e.status == EndpointStatus.DEPRECATED)

    @classmethod
    async def coverage_percent(cls, declared_count: int) -> float:
        if declared_count == 0:
            return 0.0
        known = sum(1 for e in cls._cache.values() if e.status == EndpointStatus.KNOWN)
        return round(known / declared_count * 100, 1)
