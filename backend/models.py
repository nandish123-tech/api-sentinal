"""
models.py – All Pydantic + SQLAlchemy models for API Sentinel.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import JSON, Boolean, Column, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase


# ══════════════════════════════════════════════════════════════════════════════
# Enumerations
# ══════════════════════════════════════════════════════════════════════════════

class EndpointStatus(str, Enum):
    KNOWN        = "known"           # in declared OAS contract
    UNDOCUMENTED = "undocumented"    # live traffic, not in OAS  → Shadow API
    DEPRECATED   = "deprecated"      # in OAS but marked retired, still receiving traffic


class AlertType(str, Enum):
    BOLA        = "BOLA"         # Broken Object Level Authorization
    SHADOW_API  = "SHADOW_API"   # Undocumented endpoint seen in traffic
    ENUMERATION = "ENUMERATION"  # Principal scanning many object IDs
    DEPRECATED  = "DEPRECATED"   # Traffic to a deprecated route


class Decision(str, Enum):
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    BLOCK = "BLOCK"


class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ══════════════════════════════════════════════════════════════════════════════
# SQLAlchemy ORM Base
# ══════════════════════════════════════════════════════════════════════════════

class Base(DeclarativeBase):
    pass


# ══════════════════════════════════════════════════════════════════════════════
# ORM Tables
# ══════════════════════════════════════════════════════════════════════════════

class ApiEventORM(Base):
    __tablename__ = "api_events"

    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp      = Column(DateTime, default=datetime.utcnow, index=True)
    principal_id   = Column(String, index=True)
    method         = Column(String(16))
    path           = Column(String(512))
    route_template = Column(String(512), index=True)
    object_type    = Column(String(128))
    object_id      = Column(String(256))
    status_code    = Column(Integer)
    latency_ms     = Column(Float)
    declared_match = Column(Boolean, default=True)
    user_agent     = Column(String(256))
    client_ip      = Column(String(64))
    signals        = Column(JSON, default=list)
    risk_score     = Column(Float, default=0.0)
    decision       = Column(String(16), default=Decision.ALLOW)


class SentinelAlertORM(Base):
    __tablename__ = "sentinel_alerts"

    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp      = Column(DateTime, default=datetime.utcnow, index=True)
    alert_type     = Column(String(32), index=True)
    severity       = Column(String(16))
    principal_id   = Column(String)
    method         = Column(String(16))
    route_template = Column(String(512))
    object_type    = Column(String(128))
    object_id      = Column(String(256))
    expected_owner = Column(String)
    signals        = Column(JSON, default=list)
    evidence       = Column(JSON, default=dict)
    risk_score     = Column(Float)
    decision       = Column(String(16))
    resolved       = Column(Boolean, default=False)
    notes          = Column(Text, default="")


class InventoryEntryORM(Base):
    __tablename__ = "inventory"

    route_template = Column(String(512), primary_key=True)
    method         = Column(String(16), primary_key=True)
    status         = Column(String(32), default=EndpointStatus.UNDOCUMENTED)
    first_seen     = Column(DateTime, default=datetime.utcnow)
    last_seen      = Column(DateTime, default=datetime.utcnow)
    request_count  = Column(Integer, default=0)
    tags           = Column(JSON, default=list)
    summary        = Column(String(256), default="")
    risk_score_avg = Column(Float, default=0.0)


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic Schemas (API I/O)
# ══════════════════════════════════════════════════════════════════════════════

class ApiEvent(BaseModel):
    """Normalized HTTP event emitted by the middleware."""
    id:             str       = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:      datetime  = Field(default_factory=datetime.utcnow)
    principal_id:   str       = "anonymous"
    method:         str
    path:           str
    route_template: str
    object_type:    str       = ""
    object_id:      str       = ""
    status_code:    int       = 0
    latency_ms:     float     = 0.0
    declared_match: bool      = True
    user_agent:     str       = ""
    client_ip:      str       = ""
    signals:        list[str] = Field(default_factory=list)
    risk_score:     float     = 0.0
    decision:       Decision  = Decision.ALLOW

    model_config = {"from_attributes": True}


class SentinelAlert(BaseModel):
    """Explainable alert raised by the detection engine."""
    id:             str       = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:      datetime  = Field(default_factory=datetime.utcnow)
    alert_type:     AlertType
    severity:       Severity
    principal_id:   str
    method:         str
    route_template: str
    object_type:    str       = ""
    object_id:      str       = ""
    expected_owner: str       = ""
    signals:        list[str] = Field(default_factory=list)
    evidence:       dict[str, Any] = Field(default_factory=dict)
    risk_score:     float
    decision:       Decision
    resolved:       bool      = False
    notes:          str       = ""

    model_config = {"from_attributes": True}


class InventoryEntry(BaseModel):
    """One entry in the live API inventory."""
    route_template: str
    method:         str
    status:         EndpointStatus
    first_seen:     datetime
    last_seen:      datetime
    request_count:  int
    tags:           list[str] = Field(default_factory=list)
    summary:        str       = ""
    risk_score_avg: float     = 0.0

    model_config = {"from_attributes": True}


class OwnershipRecord(BaseModel):
    """Maps an object to its owner."""
    object_type: str
    object_id:   str
    owner_id:    str
    role:        str = "owner"


class DashboardStats(BaseModel):
    total_events:       int
    total_alerts:       int
    bola_alerts:        int
    shadow_apis:        int
    deprecated_active:  int
    blocked_requests:   int
    events_per_minute:  float
    inventory_coverage: float   # 0–100 %
    top_risky_routes:   list[dict[str, Any]]
    alert_type_counts:  dict[str, int]
    severity_counts:    dict[str, int]
