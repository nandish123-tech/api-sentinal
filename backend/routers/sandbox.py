"""
routers/sandbox.py – Intentionally-vulnerable sandbox API for demonstrations.

Routes here are realistic but do NOT implement their own authorization —
all security enforcement is done exclusively by API Sentinel middleware.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from ownership import ownership_map

router = APIRouter(prefix="/api", tags=["sandbox"])

# ── Synthetic data stores ─────────────────────────────────────────────────────

_ORDERS: dict[str, dict] = {
    "101": {"id": "101", "owner": "user_101", "product": "Laptop Pro",    "amount": 1299.99, "status": "delivered"},
    "102": {"id": "102", "owner": "user_101", "product": "Mechanical KB", "amount": 149.50,  "status": "shipped"},
    "103": {"id": "103", "owner": "user_101", "product": "USB-C Hub",     "amount": 59.99,   "status": "processing"},
    "201": {"id": "201", "owner": "user_202", "product": "Monitor 4K",    "amount": 649.00,  "status": "delivered"},
    "202": {"id": "202", "owner": "user_202", "product": "Webcam HD",     "amount": 89.00,   "status": "shipped"},
    "203": {"id": "203", "owner": "user_202", "product": "Headset BT",    "amount": 199.00,  "status": "processing"},
    "301": {"id": "301", "owner": "user_303", "product": "Tablet S9",     "amount": 799.00,  "status": "delivered"},
}

_BILLING: dict[str, dict] = {
    "101": {"user_id": "101", "owner": "user_101", "card_last4": "4242", "balance": 2450.00, "currency": "USD"},
    "202": {"user_id": "202", "owner": "user_202", "card_last4": "8888", "balance": 1120.50, "currency": "USD"},
    "303": {"user_id": "303", "owner": "user_303", "card_last4": "1234", "balance": 890.75,  "currency": "USD"},
}

_USERS: dict[str, dict] = {
    "101": {"id": "101", "name": "Alice Martin",  "email": "alice@example.com",  "role": "customer"},
    "202": {"id": "202", "name": "Bob Chen",      "email": "bob@example.com",    "role": "customer"},
    "303": {"id": "303", "name": "Carol Singh",   "email": "carol@example.com",  "role": "customer"},
    "999": {"id": "999", "name": "Admin User",    "email": "admin@example.com",  "role": "admin"},
}

_PRODUCTS: list[dict] = [
    {"id": "p001", "name": "Laptop Pro",     "price": 1299.99, "stock": 42},
    {"id": "p002", "name": "Monitor 4K",     "price": 649.00,  "stock": 15},
    {"id": "p003", "name": "Mechanical KB",  "price": 149.50,  "stock": 200},
    {"id": "p004", "name": "USB-C Hub",      "price": 59.99,   "stock": 350},
    {"id": "p005", "name": "Webcam HD",      "price": 89.00,   "stock": 78},
]


# ── Orders ────────────────────────────────────────────────────────────────────

@router.get("/orders")
async def list_orders(x_user_id: str = Header(default="anonymous")):
    """List orders that belong to the authenticated user."""
    user_orders = [o for o in _ORDERS.values() if o["owner"] == f"user_{x_user_id}"]
    return {"user_id": x_user_id, "orders": user_orders, "count": len(user_orders)}


class OrderCreate(BaseModel):
    product: str
    amount: float


@router.post("/orders")
async def create_order(body: OrderCreate, x_user_id: str = Header(default="anonymous")):
    """Create a new order (ownership registered in ownership map)."""
    new_id = str(random.randint(1000, 9999))
    order = {"id": new_id, "owner": f"user_{x_user_id}", "product": body.product,
             "amount": body.amount, "status": "processing"}
    _ORDERS[new_id] = order
    ownership_map.register("order", new_id, f"user_{x_user_id}")
    return {"created": order}


@router.get("/orders/{order_id}")
async def get_order(order_id: str, x_user_id: str = Header(default="anonymous")):
    """
    Get a specific order.
    Sentinel middleware enforces BOLA — this handler trusts the middleware decision.
    """
    order = _ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail=f"Order {order_id} not found")
    return order


@router.delete("/orders/{order_id}")
async def delete_order(order_id: str, x_user_id: str = Header(default="anonymous")):
    order = _ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Not found")
    return {"deleted": order_id, "status": "cancelled"}


# ── Billing ───────────────────────────────────────────────────────────────────

@router.get("/billing/{user_id}")
async def get_billing(user_id: str, x_user_id: str = Header(default="anonymous")):
    """
    Billing is highly sensitive — cross-user access is a classic BOLA scenario.
    """
    record = _BILLING.get(user_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Billing record {user_id} not found")
    return record


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get("/users/{user_id}")
async def get_user(user_id: str, x_user_id: str = Header(default="anonymous")):
    user = _USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("/users/{user_id}/profile")
async def get_profile(user_id: str, x_user_id: str = Header(default="anonymous")):
    user = _USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"profile": user, "preferences": {"theme": "dark", "notifications": True}}


@router.put("/users/{user_id}/profile")
async def update_profile(user_id: str, body: dict[str, Any], x_user_id: str = Header(default="anonymous")):
    return {"updated": user_id, "fields": list(body.keys())}


# ── Products (public, no auth required) ──────────────────────────────────────

@router.get("/products")
async def list_products():
    return {"products": _PRODUCTS}


@router.get("/products/{product_id}")
async def get_product(product_id: str):
    product = next((p for p in _PRODUCTS if p["id"] == product_id), None)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


# ── Admin debug (intentionally undocumented — Shadow API demo) ────────────────

@router.get("/admin/debug")
async def admin_debug():
    """
    This route is NOT in the declared OpenAPI contract.
    Any request here will trigger a Shadow API alert in Sentinel.
    """
    return {
        "status": "debug",
        "timestamp": datetime.utcnow().isoformat(),
        "internal_users": list(_USERS.values()),
        "internal_orders_count": len(_ORDERS),
        "warning": "This endpoint exposes internal data and should not be publicly accessible",
    }


# ── Legacy deprecated routes ──────────────────────────────────────────────────

@router.get("/v1/legacy/orders")
async def legacy_orders():
    """Deprecated — use /api/orders instead."""
    return {"deprecated": True, "message": "Please migrate to /api/orders", "data": list(_ORDERS.values())}


@router.get("/v1/legacy/users/{user_id}")
async def legacy_user(user_id: str):
    """Deprecated — use /api/users/{user_id} instead."""
    return {"deprecated": True, "message": "Please migrate to /api/users", "user": _USERS.get(user_id)}
