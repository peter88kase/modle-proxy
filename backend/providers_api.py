"""Provider configuration CRUD (non-sensitive metadata only)."""

from __future__ import annotations

import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .adapters.base import ADAPTERS
from .db import audit, connect, now_iso
from .deps import client_ip_of, require_admin, require_csrf, require_operator
from .security import SessionContext

router = APIRouter(prefix="/api/providers", tags=["providers"])

ID_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{1,31}$")


class ProviderPayload(BaseModel):
    id: str = Field(min_length=2, max_length=32)
    name: str = Field(min_length=1, max_length=64)
    adapter: str = Field(min_length=1, max_length=32)
    direct_base_url: str = Field(default="", max_length=512)
    forward_base_url: str = Field(default="", max_length=512)
    auth_style: str = Field(default="", max_length=32)
    #: 版本号的值；空 = 由适配器按模式取默认（header 2023-06-01 / body bedrock-2023-05-31）。
    api_version: str = Field(default="", max_length=64)
    #: True = 版本号放请求体（Bedrock invoke_model 风格网关）；
    #: False = 放 header（Anthropic 直连 / bedrock-mantle）。二选一。
    version_in_body: bool = False
    default_model: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=500)
    enabled: bool = True


def _row_to_dict(row) -> dict:
    try:
        protocols = json.loads(row["protocols"])
    except (ValueError, TypeError):
        protocols = []
    return {
        "id": row["id"],
        "name": row["name"],
        "adapter": row["adapter"],
        "direct_base_url": row["direct_base_url"],
        "forward_base_url": row["forward_base_url"],
        "auth_style": row["auth_style"],
        "api_version": row["api_version"],
        "version_in_body": bool(row["version_in_body"]),
        "default_model": row["default_model"],
        "protocols": protocols,
        "notes": row["notes"],
        "enabled": bool(row["enabled"]),
        "updated_at": row["updated_at"],
    }


@router.get("")
def list_providers(session: SessionContext = Depends(require_operator)) -> dict:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM providers ORDER BY name").fetchall()
    return {"items": [_row_to_dict(row) for row in rows]}


@router.post("")
def upsert_provider(
    payload: ProviderPayload, request: Request, session: SessionContext = Depends(require_admin)
) -> dict:
    require_csrf(request, session)
    if not ID_RE.match(payload.id):
        raise HTTPException(status_code=400, detail={"code": "invalid_id", "message": "标识只能包含小写字母、数字、下划线和短横线"})
    adapter = ADAPTERS.get(payload.adapter)
    if adapter is None:
        raise HTTPException(status_code=400, detail={"code": "unknown_adapter", "message": "未知的适配器类型"})
    if payload.auth_style and payload.auth_style not in adapter.auth_styles:
        raise HTTPException(status_code=400, detail={"code": "invalid_auth_style", "message": "该适配器不支持所选的认证方式"})
    for field_name in ("direct_base_url", "forward_base_url"):
        value = getattr(payload, field_name)
        if value and not value.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail={"code": "invalid_url", "message": f"{field_name} 必须以 http:// 或 https:// 开头"})

    with connect() as conn:
        existing = conn.execute("SELECT id FROM providers WHERE id=?", (payload.id,)).fetchone()
        if existing:
            conn.execute(
                """UPDATE providers SET name=?, adapter=?, direct_base_url=?, forward_base_url=?,
                   auth_style=?, api_version=?, version_in_body=?, default_model=?, protocols=?,
                   notes=?, enabled=?, updated_at=? WHERE id=?""",
                (
                    payload.name,
                    payload.adapter,
                    payload.direct_base_url.strip(),
                    payload.forward_base_url.strip(),
                    payload.auth_style or (adapter.auth_styles[0] if adapter.auth_styles else "bearer"),
                    payload.api_version.strip(),
                    1 if payload.version_in_body else 0,
                    payload.default_model.strip(),
                    json.dumps(list(adapter.protocols), ensure_ascii=False),
                    payload.notes,
                    1 if payload.enabled else 0,
                    now_iso(),
                    payload.id,
                ),
            )
        else:
            conn.execute(
                """INSERT INTO providers(id, name, adapter, direct_base_url, forward_base_url, auth_style,
                   api_version, version_in_body, default_model, protocols, notes, enabled, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    payload.id,
                    payload.name,
                    payload.adapter,
                    payload.direct_base_url.strip(),
                    payload.forward_base_url.strip(),
                    payload.auth_style or (adapter.auth_styles[0] if adapter.auth_styles else "bearer"),
                    payload.api_version.strip(),
                    1 if payload.version_in_body else 0,
                    payload.default_model.strip(),
                    json.dumps(list(adapter.protocols), ensure_ascii=False),
                    payload.notes,
                    1 if payload.enabled else 0,
                    now_iso(),
                    now_iso(),
                ),
            )
        row = conn.execute("SELECT * FROM providers WHERE id=?", (payload.id,)).fetchone()
    audit(session.user_id, session.username, "provider_saved", client_ip_of(request), f"provider={payload.id}")
    return {"ok": True, "item": _row_to_dict(row)}


@router.delete("/{provider_id}")
def delete_provider(provider_id: str, request: Request, session: SessionContext = Depends(require_admin)) -> dict:
    require_csrf(request, session)
    with connect() as conn:
        conn.execute("DELETE FROM providers WHERE id=?", (provider_id,))
    audit(session.user_id, session.username, "provider_deleted", client_ip_of(request), f"provider={provider_id}")
    return {"ok": True}


@router.get("/adapters")
def list_adapters(session: SessionContext = Depends(require_operator)) -> dict:
    return {
        "items": [
            {
                "id": adapter.id,
                "label": adapter.label,
                "protocols": list(adapter.protocols),
                "auth_styles": list(adapter.auth_styles),
                "supports_stream": adapter.supports_stream,
                "supports_models_list": adapter.supports_models_list,
                "parameter_notes": adapter.parameter_notes,
            }
            for adapter in ADAPTERS.values()
        ]
    }
