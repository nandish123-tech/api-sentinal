"""
engine.py – Detection engine for API Sentinel.

Runs BOLA, Shadow API, Enumeration, and Deprecated-route detectors;
combines signals into a risk score; decides ALLOW / ALERT / BLOCK.
"""

from __future__ import annotations

import asyncio 
from datetime import datetime

from config import settings
from event_bus import event_bus, alert_bus
from inventory import inventory_manager, normalize_route, extract_object_info
from models import (
    ApiEvent, SentinelAlert,
    AlertType, Decision, EndpointStatus, Severity,
)
from ownership import ownership_map
from store import AlertStore, EventStore


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _severity(score: float) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 35:
        return Severity.MEDIUM
    return Severity.LOW


def _sensitive_path(route: str) -> bool:
    """Heuristic: does the route look like it handles sensitive data?"""
    keywords = {"billing", "payment", "credit", "admin", "secret", "token",
                "password", "ssn", "dob", "health", "private"}
    parts = set(route.lower().split("/"))
    return bool(keywords & parts)


def _admin_path(route: str) -> bool:
    admin_kw = {"admin", "debug", "internal", "management", "superuser", "root"}
    parts = set(route.lower().split("/"))
    return bool(admin_kw & parts)


# ══════════════════════════════════════════════════════════════════════════════
# BOLA Detector
# ══════════════════════════════════════════════════════════════════════════════

# Sensitive resource types for BOLA scoring boost
_SENSITIVE_OBJECT_TYPES = {"billing", "payment", "credit", "health", "ssn", "password", "secret", "token", "private"}


class BOLADetector:
    """
    Checks whether the authenticated principal is authorized to access the
    requested object, and whether enumeration is occurring.
    """

    async def evaluate(
        self,
        event: ApiEvent,
    ) -> tuple[list[str], float, str | None]:
        """
        Returns (signals, bola_score, expected_owner).
        bola_score=0 means no issue found.
        """
        signals: list[str] = []
        score = 0.0
        expected_owner: str | None = None

        object_type = event.object_type
        object_id   = event.object_id
        principal   = event.principal_id

        if not object_id or principal == "anonymous":
            return signals, score, expected_owner

        # 1. Ownership mismatch
        if not ownership_map.is_owner(principal, object_type, object_id):
            owner = ownership_map.get_owner(object_type, object_id)
            expected_owner = owner or "unknown"
            signals.append("ownership_mismatch")
            score += settings.w_ownership_mismatch

            # 1a. Extra signal: cross-user access to a sensitive resource type
            if object_type.lower() in _SENSITIVE_OBJECT_TYPES:
                signals.append("sensitive_resource_access")
                score += 20.0  # 50 (ownership) + 20 (sensitive) = 70 → HIGH → BLOCK

        # 2. Enumeration signal
        distinct = await EventStore.count_distinct_objects(
            principal, object_type, settings.enum_window_seconds
        )
        if distinct >= settings.enum_threshold:
            signals.append("enumeration_signal")
            score += settings.w_enumeration_signal

        return signals, min(score, 100.0), expected_owner


# ══════════════════════════════════════════════════════════════════════════════
# Shadow API Detector
# ══════════════════════════════════════════════════════════════════════════════

class ShadowAPIDetector:
    """Classifies routes against the declared OAS inventory."""

    async def evaluate(
        self,
        event: ApiEvent,
        status: EndpointStatus,
    ) -> tuple[list[str], float]:
        signals: list[str] = []
        score = 0.0

        if status == EndpointStatus.UNDOCUMENTED:
            signals.append("endpoint_novelty")
            score += settings.w_endpoint_novelty
            if _sensitive_path(event.route_template):
                signals.append("sensitive_data_exposure")
                score += settings.w_sensitive_data_signal
            if _admin_path(event.route_template):
                signals.append("admin_function_signal")
                score += settings.w_admin_function_signal

        elif status == EndpointStatus.DEPRECATED:
            signals.append("deprecated_endpoint_active")
            score += 20.0

        return signals, min(score, 100.0)


# ══════════════════════════════════════════════════════════════════════════════
# Detection Engine (orchestrator)
# ══════════════════════════════════════════════════════════════════════════════

class DetectionEngine:
    """
    Subscribes to the event bus and runs all detectors on each ApiEvent.
    """

    def __init__(self) -> None:
        self._bola    = BOLADetector()
        self._shadow  = ShadowAPIDetector()
        self._running = False

    async def start(self) -> None:
        self._running = True
        q = await event_bus.subscribe()
        asyncio.create_task(self._process_loop(q))

    async def _process_loop(self, q: asyncio.Queue) -> None:
        async for raw_event in event_bus.stream(q):
            if not self._running:
                break
            try:
                await self._evaluate(raw_event)
            except Exception as exc:
                print(f"[engine] Error processing event: {exc}")

    async def _evaluate(self, event: ApiEvent) -> ApiEvent:
        all_signals: list[str] = []
        total_score = 0.0

        # ── Inventory classification ──────────────────────────────────────────
        status = await inventory_manager.observe(
            event.method, event.route_template, risk_score=0.0
        )
        event.declared_match = status == EndpointStatus.KNOWN

        # ── BOLA check ────────────────────────────────────────────────────────
        bola_signals, bola_score, expected_owner = await self._bola.evaluate(event)
        all_signals.extend(bola_signals)
        total_score = max(total_score, bola_score)

        # ── Shadow / Deprecated check ─────────────────────────────────────────
        shadow_signals, shadow_score = await self._shadow.evaluate(event, status)
        all_signals.extend(shadow_signals)
        total_score = max(total_score, shadow_score)

        event.signals    = all_signals
        event.risk_score = round(total_score, 2)

        # ── Decision ──────────────────────────────────────────────────────────
        if total_score >= settings.anomaly_score_threshold and all_signals:
            if settings.enforcement_mode:
                event.decision = Decision.BLOCK
            else:
                event.decision = Decision.ALERT
        elif all_signals:
            event.decision = Decision.ALERT
        else:
            event.decision = Decision.ALLOW

        # ── Persist event ──────────────────────────────────────────────────────
        await EventStore.insert(event)

        # ── Update inventory with real risk score ─────────────────────────────
        await inventory_manager.observe(event.method, event.route_template, risk_score=total_score)

        # ── Raise alerts ───────────────────────────────────────────────────────
        if event.decision in (Decision.ALERT, Decision.BLOCK):
            await self._raise_alerts(event, status, bola_signals, shadow_signals,
                                     expected_owner, total_score)

        return event

    async def _raise_alerts(
        self,
        event: ApiEvent,
        status: EndpointStatus,
        bola_signals: list[str],
        shadow_signals: list[str],
        expected_owner: str | None,
        score: float,
    ) -> None:
        alerts_to_raise: list[SentinelAlert] = []

        # BOLA alert
        if bola_signals:
            alert_type = AlertType.ENUMERATION if "enumeration_signal" in bola_signals and "ownership_mismatch" not in bola_signals else AlertType.BOLA
            alerts_to_raise.append(SentinelAlert(
                alert_type=alert_type,
                severity=_severity(score),
                principal_id=event.principal_id,
                method=event.method,
                route_template=event.route_template,
                object_type=event.object_type,
                object_id=event.object_id,
                expected_owner=expected_owner or "",
                signals=bola_signals,
                evidence={
                    "requested_object": f"{event.object_type}:{event.object_id}",
                    "expected_owner":   expected_owner,
                    "actual_principal": event.principal_id,
                    "method":           event.method,
                    "path":             event.path,
                    "timestamp":        event.timestamp.isoformat(),
                    "client_ip":        event.client_ip,
                },
                risk_score=score,
                decision=event.decision,
            ))

        # Shadow / Deprecated alert
        if shadow_signals:
            at = AlertType.DEPRECATED if status == EndpointStatus.DEPRECATED else AlertType.SHADOW_API
            alerts_to_raise.append(SentinelAlert(
                alert_type=at,
                severity=_severity(score),
                principal_id=event.principal_id,
                method=event.method,
                route_template=event.route_template,
                object_type=event.object_type,
                object_id=event.object_id,
                signals=shadow_signals,
                evidence={
                    "route_template":    event.route_template,
                    "declared_match":    event.declared_match,
                    "endpoint_status":   status.value,
                    "is_admin_path":     _admin_path(event.route_template),
                    "is_sensitive_path": _sensitive_path(event.route_template),
                    "path":              event.path,
                    "timestamp":         event.timestamp.isoformat(),
                    "client_ip":         event.client_ip,
                },
                risk_score=score,
                decision=event.decision,
            ))

        for alert in alerts_to_raise:
            await AlertStore.insert(alert)
            await alert_bus.publish(alert)

    async def process_event_sync(self, event: ApiEvent) -> ApiEvent:
        """Evaluate an event synchronously (used by middleware for blocking decisions)."""
        return await self._evaluate(event)


# ── Singleton ─────────────────────────────────────────────────────────────────
detection_engine = DetectionEngine()


