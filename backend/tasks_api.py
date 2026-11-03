"""供应商验收任务接口：创建、进度、取消、重测、人工确认、证据上传。

安全约束（与 tasks.py 一起构成完整链路）：
* 创建任务时只把非敏感配置写入数据库，API Key 交给后台任务的内存运行时；
* 页面没有任何接口能读回原始 Key；
* 证据上传走 JSON + base64，避免引入 multipart 依赖，同时限制大小与扩展名；
* 所有读写都校验任务归属（operator 只看自己的，admin 可看全部）。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import tasks
from .adapters.base import ADAPTERS
from .config import settings
from .db import audit, connect, now_iso
from .deps import client_ip_of, require_admin, require_csrf, require_operator
from .security import SessionContext, redact_text
from .standards import (
    BLOCKED,
    FAIL,
    NOT_APPLICABLE,
    NOT_TESTED,
    PASS,
    PENDING,
    STATUS_LABELS,
    conclusion,
    get_version,
    list_versions,
    load_run_items,
    resolve_entries,
)

router = APIRouter(prefix="/api", tags=["tasks"])

MAX_CONCURRENT_TASKS = max(1, min(2, settings.model_max_concurrency))
#: 单次批量提交允许的最大模型数。上限存在的理由不是性能，而是**误操作保护**：
#: 一次勾 50 个模型会排出几十个批次、打满预算，而且很难判断结果从哪来。
MAX_BATCH_MODELS = 20
EVIDENCE_MAX_BYTES = 2 * 1024 * 1024
EVIDENCE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".txt", ".log", ".json", ".csv", ".md"}
MANUAL_STATUSES = {PASS, FAIL, PENDING, NOT_APPLICABLE, BLOCKED}
NOTE_REQUIRED = {FAIL, NOT_APPLICABLE, BLOCKED}

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._\u4e00-\u9fff-]+")


# --------------------------------------------------------------------------
# 模型
# --------------------------------------------------------------------------
class TaskOptions(BaseModel):
    links: list[Literal["direct", "forward"]] = Field(default_factory=lambda: ["direct"])
    forward_base_url: str = Field(default="", max_length=512)
    forward_model: str = Field(default="", max_length=200)
    forward_api_key: str = Field(default="", max_length=4096, repr=False)
    repeat: int = Field(default=3, ge=1, le=5)
    total_timeout: float = Field(default=60, ge=3, le=300)
    first_token_timeout: float = Field(default=30, ge=3, le=300)
    #: 相邻两次上游请求的最小间隔（秒）。0 = 不限速；None = 用部署默认值
    #: （`MODEL_REQUEST_INTERVAL`，默认 2s）。
    #: 背靠背发请求会撞网关 RPM 限制，429 一旦写进判定就成了"我们的节奏算供应商的错"。
    request_interval: float | None = Field(default=None, ge=0, le=30)
    connect_timeout: float = Field(default=10, ge=1, le=60)
    max_tokens: int = Field(default=64, ge=1, le=8192)
    prompt: str = Field(default="只回复 CONNECT_OK", max_length=4000)
    stream_usage: bool = False
    cache_tests: bool = True
    capability_tests: bool = True
    no_auth: bool = False
    prompt_cache_key: str = Field(default="", max_length=200)


class TaskBudget(BaseModel):
    max_requests: int = Field(default=200, ge=5, le=500)
    max_seconds: float = Field(default=900, ge=60, le=3600)


class CreateTaskPayload(BaseModel):
    name: str = Field(default="", max_length=120)
    provider_id: str = Field(default="custom", max_length=64)
    adapter: str = Field(default="", max_length=32)
    base_url: str = Field(min_length=8, max_length=512)
    model: str = Field(default="", max_length=200)
    #: 多模型批量：一次提交跑多个模型。**每个模型一个独立任务/批次**，
    #: 因为 `run_items` 对 `(run_id, item_id)` 唯一——同一批次里塞不下
    #: 多个模型的同一个用例。空 = 只跑 `model`。
    models: list[str] = Field(default_factory=list, max_length=50)
    api_key: str = Field(default="", max_length=4096, repr=False)
    auth_style: str = Field(default="", max_length=32)
    standard_version_id: int | None = Field(default=None, ge=1)
    options: TaskOptions = Field(default_factory=TaskOptions)
    budget: TaskBudget = Field(default_factory=TaskBudget)


class DetectPayload(BaseModel):
    base_url: str = Field(min_length=8, max_length=512)
    api_key: str = Field(default="", max_length=4096, repr=False)


class RetestPayload(BaseModel):
    scope: Literal["task", "chapter"] = "task"
    chapter: int | None = Field(default=None, ge=1, le=4)
    api_key: str = Field(default="", max_length=4096, repr=False)
    forward_api_key: str = Field(default="", max_length=4096, repr=False)
    options: TaskOptions | None = None
    budget: TaskBudget | None = None


class SingleRunPayload(BaseModel):
    api_key: str = Field(default="", max_length=4096, repr=False)
    forward_api_key: str = Field(default="", max_length=4096, repr=False)


class ManualPayload(BaseModel):
    status: str = Field(min_length=2, max_length=32)
    actual: str = Field(default="", max_length=1000)
    note: str = Field(default="", max_length=1000)


class BulkDeletePayload(BaseModel):
    """批量删除请求。

    两种模式互斥：`all=true` 需要确认词；否则按 `task_ids` 删选中项。
    """

    all: bool = False
    confirm: str | None = Field(default=None, max_length=32)
    task_ids: list[int] | None = Field(default=None, max_length=500)


MAX_BULK_DELETE = 200


class EvidencePayload(BaseModel):
    item_id: str = Field(min_length=1, max_length=40)
    filename: str = Field(min_length=1, max_length=160)
    content_base64: str = Field(min_length=1)
    note: str = Field(default="", max_length=300)


# --------------------------------------------------------------------------
# 权限与查询辅助
# --------------------------------------------------------------------------
def _task_or_404(task_id: int) -> dict[str, Any]:
    task = tasks.task_by_id(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "任务不存在"})
    return task


def _assert_can_view(session: SessionContext, task: dict[str, Any]) -> None:
    if session.role == "admin":
        return
    if int(task.get("user_id") or 0) != session.user_id:
        raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "无权访问该任务"})


def _assert_can_edit(session: SessionContext, task: dict[str, Any]) -> None:
    _assert_can_view(session, task)
    if session.role not in {"admin", "operator"}:
        raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "当前角色只能查看"})


def _latest_standard():
    versions = list_versions()
    return get_version(int(versions[0]["id"])) if versions else None


def _standard_for(task: dict[str, Any]):
    version_id = task.get("standard_version_id")
    return get_version(int(version_id)) if version_id else None


def _phase_summary(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    phases = []
    for chapter in (1, 2, 3, 4):
        subset = [e for e in entries if int(e["chapter"]) == chapter and e["execution"] == "auto"]
        done = [e for e in subset if e["status"] not in {NOT_TESTED, BLOCKED} and e.get("updated_at")]
        phases.append(
            {
                "key": f"ch{chapter}",
                "label": tasks.PHASE_LABELS[f"ch{chapter}"],
                "total": len(subset),
                "done": len(done),
                "status": "done" if subset and len(done) >= len(subset) else ("running" if done else "pending"),
            }
        )
    return phases


def _batch_summary(task: dict[str, Any], selected_model: str = "") -> dict[str, Any] | None:
    """任务内多模型明细（新）或历史批次其它任务（旧），供详情页切换模型与导出合并报告。"""
    task_id = int(task["id"])
    rows = tasks.task_runs(task_id)
    if len(rows) >= 2:
        current = selected_model or str(rows[0]["model"])
        return {
            "batch_id": f"TASK-{task_id}",
            "kind": "task",
            "task_id": task_id,
            "size": len(rows),
            "models": [
                {
                    "task_id": task_id,
                    "run_id": int(row["run_id"]),
                    "model": str(row.get("model") or ""),
                    "status": str(row.get("status") or ""),
                    "status_label": str(row.get("status_label") or ""),
                    "conclusion": str(row.get("conclusion") or ""),
                    "counts": row.get("counts") or {},
                    "is_current": str(row.get("model")) == current,
                }
                for row in rows
            ],
        }

    # 历史任务：一次提交的多个模型仍是多个 task，用 batch_id 归组。
    batch_id = str(task.get("batch_id") or "")
    if not batch_id:
        return None
    siblings = tasks.latest_per_model(tasks.batch_tasks(batch_id))
    if len(siblings) < 2:
        return None
    current_model = selected_model or str(task.get("model") or "")
    return {
        "batch_id": batch_id,
        "kind": "batch",
        "size": len(siblings),
        "models": [
            {
                "task_id": int(row["id"]),
                "run_id": int(row["run_id"]) if row.get("run_id") else None,
                "model": str(row.get("model") or ""),
                "status": str(row.get("status") or ""),
                "status_label": str(row.get("status_label") or ""),
                "conclusion": str(row.get("conclusion") or ""),
                "counts": row.get("counts") or {},
                "is_current": str(row.get("model")) == current_model,
            }
            for row in siblings
        ],
    }


def task_detail(task: dict[str, Any], model: str = "") -> dict[str, Any]:
    task_id = int(task["id"])
    rows = tasks.task_runs(task_id)
    selected = model or (str(rows[0]["model"]) if rows else str(task.get("model") or ""))
    selected_row = next((row for row in rows if str(row["model"]) == selected), None)
    run_id = int(selected_row["run_id"]) if selected_row else task.get("run_id")
    version = _standard_for(task)
    if version is None or not run_id:
        return {
            "task": task,
            "selected_model": selected,
            "models": [str(row["model"]) for row in rows] or tasks.task_model_list(task),
            "entries": [],
            "conclusion": None,
            "phases": [],
            "evidence": [],
            "retests": [],
            "metrics": (selected_row or {}).get("metrics") or {},
            "batch": _batch_summary(task, selected),
        }
    entries = _entries_for_run(run_id, version)
    verdict = conclusion(resolve_entries(version, load_run_items(run_id)))
    return {
        "task": task,
        "selected_model": selected,
        "models": [str(row["model"]) for row in rows] or tasks.task_model_list(task),
        "standard": {
            "id": version.id,
            "version": version.version,
            "checksum": version.checksum,
            "item_count": version.item_count,
        },
        "entries": entries,
        "conclusion": verdict,
        "phases": _phase_summary(entries),
        "evidence": tasks.evidence_for(task_id),
        "retests": tasks.retest_history(task_id),
        # 前置必测产出的渠道指标（P5/中位/P95、缓存命中率），供渠道权重与页面展示。
        "metrics": (selected_row or {}).get("metrics") or {},
        "status_labels": STATUS_LABELS,
        "batch": _batch_summary(task, selected),
    }


def _entries_for_run(run_id: int, version) -> list[dict[str, Any]]:
    return [entry.as_dict() for entry in resolve_entries(version, load_run_items(run_id))]


# --------------------------------------------------------------------------
# 协议识别
# --------------------------------------------------------------------------
_ADAPTER_HINTS = (
    ("anthropic", ("anthropic", "claude")),
    ("gemini", ("generativelanguage", "gemini", "googleapis")),
)


def _guess_adapter(url: str) -> str | None:
    lowered = url.lower()
    for adapter_id, keywords in _ADAPTER_HINTS:
        if any(keyword in lowered for keyword in keywords):
            return adapter_id
    return None


async def _probe_models(base_url: str, api_key: str, auth_style: str) -> list[str]:
    """GET {base}/models：能列模型说明至少是 OpenAI 兼容形态。"""
    url = base_url.rstrip("/")
    for path in ("/models", "/v1/models"):
        target = url + path if not url.endswith("/v1") else url + "/models"
        headers = {"Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            async with httpx.AsyncClient(timeout=6, follow_redirects=False) as client:
                response = await client.get(target, headers=headers)
        except Exception:  # noqa: BLE001 - 探测失败不抛给用户
            continue
        if response.status_code != 200:
            continue
        try:
            payload = response.json()
        except ValueError:
            continue
        items = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(items, list) and items:
            return ["openai"]
        models = payload.get("models") if isinstance(payload, dict) else None
        if isinstance(models, list) and models:
            return ["gemini"]
    return []


@router.post("/tasks/detect")
async def detect_adapter(payload: DetectPayload, request: Request, session: SessionContext = Depends(require_operator)) -> dict:
    require_csrf(request, session)
    guesses = [g for g in [_guess_adapter(payload.base_url)] if g]
    probed = await _probe_models(payload.base_url, payload.api_key, "")
    payload.api_key = ""
    candidates = list(dict.fromkeys([*probed, *guesses]))
    if len(candidates) == 1:
        return {"adapter": candidates[0], "candidates": candidates, "message": ""}
    if len(candidates) > 1:
        return {
            "adapter": None,
            "candidates": candidates,
            "message": "探测到多种可能的协议，请手动选择",
        }
    return {
        "adapter": None,
        "candidates": [adapter.id for adapter in ADAPTERS.values()],
        "message": "无法自动识别协议（端点未返回模型列表），请手动选择",
    }


# --------------------------------------------------------------------------
# 创建 / 启动
# --------------------------------------------------------------------------
def _build_options(payload: CreateTaskPayload) -> dict[str, Any]:
    options = payload.options
    if "forward" in options.links and not options.forward_base_url.strip():
        raise HTTPException(
            status_code=400,
            detail={"code": "missing_forward", "message": "选择转发链路时必须填写 Fluxlane 转发地址"},
        )
    return {
        "links": list(dict.fromkeys(options.links)),
        "base_url": payload.base_url.strip(),
        "forward_base_url": options.forward_base_url.strip(),
        "forward_model": options.forward_model.strip(),
        "auth_style": payload.auth_style,
        "repeat": options.repeat,
        "total_timeout": options.total_timeout,
        "first_token_timeout": options.first_token_timeout,
        "connect_timeout": options.connect_timeout,
        "max_tokens": options.max_tokens,
        "prompt": options.prompt,
        "stream_usage": options.stream_usage,
        "cache_tests": options.cache_tests,
        "capability_tests": options.capability_tests,
        "no_auth": options.no_auth,
        "prompt_cache_key": options.prompt_cache_key,
    }


def _new_run_row(task_name: str, provider_id: str, adapter: str, model: str, host: str, link: str,
                 user_id: int, version) -> int:
    with connect() as conn:
        cursor = conn.execute(
            """INSERT INTO suite_runs(created_at, user_id, provider_id, provider_name, adapter, link, model,
               endpoint_host, passed, failed, skipped, note,
               standard_version_id, standard_version, standard_checksum, conclusion)
               VALUES (?,?,?,?,?,?,?,?,0,0,0,'',?,?,?,'')""",
            (
                now_iso(),
                user_id,
                provider_id,
                task_name,
                adapter,
                link,
                model,
                host,
                version.id if version else None,
                version.version if version else "",
                version.checksum if version else "",
            ),
        )
        return int(cursor.lastrowid)


def _launch_multi(task_id: int, task: dict[str, Any], runs: list[dict[str, Any]], api_key: str,
                  forward_key: str, budget: dict[str, Any]) -> None:
    """为一个任务的多个模型分别构建配置，然后整体交给引擎顺序执行。"""
    entries: list[tasks.ModelRun] = []
    explicit_forward_model = str((task.get("options") or {}).get("forward_model") or "")
    for row in runs:
        cfg = tasks.build_suite_config(task, api_key, forward_key)
        cfg.model = str(row["model"])
        if not (explicit_forward_model and len(runs) == 1):
            cfg.forward_model = str(row["model"])
        entries.append(tasks.ModelRun(model=str(row["model"]), cfg=cfg, run_id=int(row["run_id"])))
    try:
        tasks.start_task_multi(task_id, entries, budget)
    except tasks.TaskError as exc:
        raise HTTPException(status_code=409, detail={"code": exc.code, "message": exc.message}) from exc


@router.post("/tasks")
async def create_task(payload: CreateTaskPayload, request: Request, session: SessionContext = Depends(require_operator)) -> dict:
    require_csrf(request, session)
    if tasks.active_task_ids() and len(tasks.active_task_ids()) >= MAX_CONCURRENT_TASKS:
        raise HTTPException(
            status_code=429,
            detail={"code": "busy", "message": f"当前已有 {len(tasks.active_task_ids())} 个任务在执行，请稍后重试"},
        )
    adapter_id = payload.adapter.strip().lower()
    if not adapter_id:
        raise HTTPException(
            status_code=400,
            detail={"code": "adapter_required", "message": "请选择接口协议（无法自动确定时不允许执行）"},
        )
    if adapter_id not in ADAPTERS:
        raise HTTPException(status_code=400, detail={"code": "unknown_adapter", "message": "未知的接口协议"})
    if not payload.options.no_auth and not payload.api_key.strip():
        raise HTTPException(status_code=400, detail={"code": "missing_key", "message": "请填写 API Key（无需鉴权的端点请勾选“该端点无需鉴权”）"})

    version = get_version(payload.standard_version_id) if payload.standard_version_id else _latest_standard()
    if version is None:
        raise HTTPException(status_code=409, detail={"code": "standard_missing", "message": "没有可用的测试标准版本"})

    options = _build_options(payload)
    link_label = "+".join(options["links"])

    # 多模型 = 一个任务：任务内每个模型各有一条 suite_runs（run_items 对
    # (run_id,item_id) 唯一，同一用例的多模型结果必须分表存），但生命周期、删除、
    # 报告都归到同一个 task_id。旧的"每个模型一个任务 + batch_id"仅保留给历史数据。
    raw = [m.strip() for m in (payload.models or []) if m.strip()]
    if not raw and payload.model.strip():
        raw = [payload.model.strip()]
    seen: set[str] = set()
    targets: list[str] = []
    for model in raw:
        if model not in seen:
            seen.add(model)
            targets.append(model)
    if not targets:
        raise HTTPException(
            status_code=400,
            detail={"code": "model_required", "message": "请至少指定一个模型"},
        )
    if len(targets) > MAX_BATCH_MODELS:
        raise HTTPException(
            status_code=400,
            detail={"code": "too_many_models", "message": f"单次最多 {MAX_BATCH_MODELS} 个模型"},
        )

    base_name = payload.name.strip()
    try:
        task_id = tasks.create_task(
            user_id=session.user_id,
            username=session.username,
            name=base_name or f"{adapter_id}:{targets[0]}",
            provider_id=payload.provider_id or "custom",
            adapter=adapter_id,
            model=targets[0],
            models=targets,
            base_url=payload.base_url.strip(),
            standard=version,
            options=options,
            budget=payload.budget.model_dump(),
        )
    except tasks.TaskError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message}) from exc

    task = tasks.task_by_id(task_id)
    assert task is not None
    runs: list[dict[str, Any]] = []
    for model in targets:
        label = f"{base_name} · {model}" if (len(targets) > 1 and base_name) else (base_name or model)
        run_id = _new_run_row(
            label,
            payload.provider_id or "custom",
            adapter_id,
            model,
            str(task["endpoint_host"]),
            link_label,
            session.user_id,
            version,
        )
        tasks.add_task_run(task_id, model, run_id)
        runs.append({"model": model, "run_id": run_id, "task_id": task_id})

    with connect() as conn:
        conn.execute("UPDATE test_tasks SET run_id=? WHERE id=?", (runs[0]["run_id"], task_id))
    task = tasks.task_by_id(task_id)
    assert task is not None

    _launch_multi(task_id, task, runs, payload.api_key, payload.options.forward_api_key,
                  payload.budget.model_dump())

    audit(
        session.user_id,
        session.username,
        "task_created",
        client_ip_of(request),
        f"task={task_id} models={','.join(targets)} adapter={adapter_id} host={task['endpoint_host']}",
    )
    payload.api_key = ""
    return {
        "task": tasks.task_by_id(task_id),
        "run_id": runs[0]["run_id"],
        "models": runs,
        # 历史字段：单模型时长度为 1，前端旧版本可继续读取。
        "tasks": runs,
        "batch_id": "",
    }


@router.get("/models/groups")
def list_model_groups(session: SessionContext = Depends(require_operator)) -> dict:
    """模型组清单，供「批量验收」界面提示。

    **这不是白名单**：平台不限制只能测这些 ID，也不保证供应商一定提供。
    真实可用性以 provider 的 `/models` 接口或供应商文档为准。
    """
    path = Path(__file__).resolve().parents[1] / "config" / "model_groups.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"groups": []}
    return {"groups": data.get("groups", [])}


@router.get("/tasks")
def list_tasks(limit: int = 50, session: SessionContext = Depends(require_operator)) -> dict:
    """任务列表。

    ``total`` 是**当前身份可见的任务总数**，不受 ``limit`` 影响。
    为什么必须单独给这个数：列表只显示最近 N 条，而「删除全部」是不可逆操作，
    它的确认文案必须按真实总数说。前端拿 `items.length` 当总数时，库里有 205 条、
    列表只显示 50 条，弹窗就会写"会删除全部 50 个"——把影响范围说小了 4 倍。
    """
    is_admin = session.role == "admin"
    items = tasks.list_tasks(session.user_id, is_admin, limit)
    with connect() as conn:
        if is_admin or session.user_id is None:
            total = int(conn.execute("SELECT COUNT(*) c FROM test_tasks").fetchone()["c"])
        else:
            total = int(
                conn.execute("SELECT COUNT(*) c FROM test_tasks WHERE user_id=?", (session.user_id,)).fetchone()["c"]
            )
    return {
        "items": items,
        "total": total,
        "active": tasks.active_task_ids(),
        "labels": tasks.TASK_STATUS_LABELS,
    }


@router.get("/tasks/{task_id}")
def get_task(task_id: int, model: str = "", session: SessionContext = Depends(require_operator)) -> dict:
    task = _task_or_404(task_id)
    _assert_can_view(session, task)
    known = [str(row["model"]) for row in tasks.task_runs(task_id)] or tasks.task_model_list(task)
    if model and model not in known:
        raise HTTPException(status_code=404, detail={"code": "model_not_found", "message": "该任务不包含此模型"})
    return task_detail(task, model)


@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: int, request: Request, session: SessionContext = Depends(require_operator)) -> dict:
    require_csrf(request, session)
    task = _task_or_404(task_id)
    _assert_can_edit(session, task)
    stopped = tasks.cancel_task(task_id, f"{session.username} 取消")
    if not stopped:
        raise HTTPException(status_code=409, detail={"code": "not_running", "message": "任务当前不在执行中"})
    audit(session.user_id, session.username, "task_cancelled", client_ip_of(request), f"task={task_id}")
    return {"ok": True, "task_id": task_id}


@router.post("/tasks/{task_id}/retest")
async def retest_task(
    task_id: int,
    payload: RetestPayload,
    request: Request,
    session: SessionContext = Depends(require_operator),
) -> dict:
    require_csrf(request, session)
    old = _task_or_404(task_id)
    _assert_can_edit(session, old)
    if tasks.is_running(task_id):
        raise HTTPException(status_code=409, detail={"code": "already_running", "message": "任务正在执行，不能重测"})
    if not payload.api_key.strip() and not (old.get("options") or {}).get("no_auth"):
        raise HTTPException(status_code=400, detail={"code": "missing_key", "message": "重测需要重新填写 API Key（平台不保存明文密钥）"})

    version = _standard_for(old)
    if version is None:
        raise HTTPException(status_code=409, detail={"code": "standard_missing", "message": "任务未绑定测试标准"})

    options = dict(old.get("options") or {})
    if payload.options is not None:
        incoming = payload.options
        if "forward" in incoming.links and not incoming.forward_base_url.strip():
            raise HTTPException(
                status_code=400,
                detail={"code": "missing_forward", "message": "选择转发链路时必须填写 Fluxlane 转发地址"},
            )
        options.update(
            {
                "links": list(dict.fromkeys(incoming.links)),
                "forward_base_url": incoming.forward_base_url.strip(),
                "forward_model": incoming.forward_model.strip(),
                "repeat": incoming.repeat,
                "total_timeout": incoming.total_timeout,
                "first_token_timeout": incoming.first_token_timeout,
                "connect_timeout": incoming.connect_timeout,
                "max_tokens": incoming.max_tokens,
                "prompt": incoming.prompt,
                "stream_usage": incoming.stream_usage,
                "cache_tests": incoming.cache_tests,
                "capability_tests": incoming.capability_tests,
                "no_auth": incoming.no_auth,
            }
        )
    if payload.scope == "chapter":
        if payload.chapter is None:
            raise HTTPException(status_code=400, detail={"code": "chapter_required", "message": "请选择要重测的章节"})
        options["scope"] = {"type": "chapter", "chapter": payload.chapter}
    else:
        options["scope"] = {"type": "task"}

    models = tasks.task_model_list(old)
    try:
        new_id = tasks.create_task(
            user_id=session.user_id,
            username=session.username,
            name=f"{old['name']}（重测 {int(old.get('attempt') or 1) + 1}）",
            provider_id=str(old.get("provider_id") or "custom"),
            adapter=str(old["adapter"]),
            model=models[0],
            models=models,
            base_url=str(options.get("base_url") or ""),
            standard=version,
            options=options,
            budget=(payload.budget.model_dump() if payload.budget else old.get("budget")),
            parent_task_id=task_id,
            attempt=int(old.get("attempt") or 1) + 1,
        )
    except tasks.TaskError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message}) from exc

    task = tasks.task_by_id(new_id)
    assert task is not None
    runs: list[dict[str, Any]] = []
    for model in models:
        run_label = str(task["name"]) if len(models) == 1 else f"{task['name']} · {model}"
        run_id = _new_run_row(
            run_label,
            str(task.get("provider_id") or "custom"),
            str(old["adapter"]),
            model,
            str(task["endpoint_host"]),
            str(task.get("link") or "direct"),
            session.user_id,
            version,
        )
        tasks.add_task_run(new_id, model, run_id)
        runs.append({"model": model, "run_id": run_id, "task_id": new_id})
    with connect() as conn:
        conn.execute("UPDATE test_tasks SET run_id=? WHERE id=?", (runs[0]["run_id"], new_id))
    task = tasks.task_by_id(new_id)
    assert task is not None

    budget_payload = payload.budget.model_dump() if payload.budget else (old.get("budget") or tasks.DEFAULT_BUDGET)
    _launch_multi(new_id, task, runs, payload.api_key, payload.forward_api_key, budget_payload)
    payload.api_key = ""
    audit(
        session.user_id,
        session.username,
        "task_retested",
        client_ip_of(request),
        f"task={new_id} parent={task_id} scope={options['scope']} models={','.join(models)}",
    )
    return {
        "task": tasks.task_by_id(new_id),
        "run_id": runs[0]["run_id"],
        "models": runs,
        "parent_task_id": task_id,
    }


@router.post("/tasks/{task_id}/items/{item_id}/run")
async def run_item(
    task_id: int,
    item_id: str,
    payload: SingleRunPayload,
    request: Request,
    model: str = "",
    session: SessionContext = Depends(require_operator),
) -> dict:
    require_csrf(request, session)
    task = _task_or_404(task_id)
    _assert_can_edit(session, task)
    if not payload.api_key.strip() and not (task.get("options") or {}).get("no_auth"):
        raise HTTPException(status_code=400, detail={"code": "missing_key", "message": "执行单项测试需要 API Key（平台不保存明文密钥）"})
    try:
        result = await tasks.run_single_item(task_id, item_id, payload.api_key, payload.forward_api_key, model)
    except tasks.TaskError as exc:
        status = 404 if exc.code == "not_found" else 409 if exc.code in {"already_running", "suite_required"} else 400
        raise HTTPException(status_code=status, detail={"code": exc.code, "message": exc.message}) from exc
    finally:
        payload.api_key = ""
    audit(
        session.user_id,
        session.username,
        "task_item_retested",
        client_ip_of(request),
        f"task={task_id} model={result.get('model') or model or '-'} item={item_id} status={result['status']}",
    )
    return result


@router.post("/tasks/{task_id}/items/{item_id}")
def update_item(
    task_id: int,
    item_id: str,
    payload: ManualPayload,
    request: Request,
    model: str = "",
    session: SessionContext = Depends(require_operator),
) -> dict:
    require_csrf(request, session)
    task = _task_or_404(task_id)
    _assert_can_edit(session, task)
    version = _standard_for(task)
    if version is None or item_id not in version.items:
        raise HTTPException(status_code=404, detail={"code": "item_not_found", "message": "测试项不存在"})
    if payload.status not in MANUAL_STATUSES:
        raise HTTPException(status_code=400, detail={"code": "invalid_status", "message": f"不支持的状态：{payload.status}"})
    if payload.status in NOTE_REQUIRED and not payload.note.strip():
        raise HTTPException(status_code=400, detail={"code": "note_required", "message": "标记为不通过/不适用/阻塞时必须填写说明"})

    row = tasks.task_run_for(task_id, model)
    selected_model = str(row["model"]) if row else str(task.get("model") or "")
    run_id = int(row["run_id"]) if row else int(task["run_id"])
    with connect() as conn:
        previous = conn.execute(
            "SELECT status, actual FROM run_items WHERE run_id=? AND item_id=?", (run_id, item_id)
        ).fetchone()
        conn.execute(
            """INSERT INTO run_items(run_id, item_id, status, source, actual, evidence, note, operator, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(run_id, item_id) DO UPDATE SET
                 status=excluded.status, actual=excluded.actual, note=excluded.note,
                 operator=excluded.operator, updated_at=excluded.updated_at, source='manual'""",
            (
                run_id,
                item_id,
                payload.status,
                "manual",
                payload.actual.strip()[:1000],
                "",
                payload.note.strip()[:1000],
                session.username,
                now_iso(),
            ),
        )
    tasks.record_retest(task_id, item_id, "manual", previous, payload.status, payload.actual, session.username)
    verdict = tasks.recompute(task_id, selected_model)
    audit(
        session.user_id,
        session.username,
        "task_item_manual",
        client_ip_of(request),
        f"task={task_id} model={selected_model or '-'} item={item_id} status={payload.status}",
    )
    return {"ok": True, "item_id": item_id, "model": selected_model, "conclusion": verdict}


# --------------------------------------------------------------------------
# 证据上传
# --------------------------------------------------------------------------
def _evidence_root() -> Path:
    root = settings.db_path.parent / "evidence"
    root.mkdir(parents=True, exist_ok=True)
    return root


@router.post("/tasks/{task_id}/evidence")
def upload_evidence(
    task_id: int,
    payload: EvidencePayload,
    request: Request,
    session: SessionContext = Depends(require_operator),
) -> dict:
    require_csrf(request, session)
    task = _task_or_404(task_id)
    _assert_can_edit(session, task)
    version = _standard_for(task)
    if version is None or payload.item_id not in version.items:
        raise HTTPException(status_code=404, detail={"code": "item_not_found", "message": "测试项不存在"})

    raw_name = Path(payload.filename).name
    suffix = Path(raw_name).suffix.lower()
    if suffix not in EVIDENCE_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail={"code": "unsupported_type", "message": f"不支持的文件类型：{suffix or '无扩展名'}"},
        )
    try:
        data = base64.b64decode(payload.content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail={"code": "invalid_base64", "message": "文件内容不是合法的 base64"}) from exc
    if not data:
        raise HTTPException(status_code=400, detail={"code": "empty_file", "message": "文件内容为空"})
    if len(data) > EVIDENCE_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"code": "too_large", "message": f"证据文件不能超过 {EVIDENCE_MAX_BYTES // 1024 // 1024} MB"},
        )

    safe_name = _SAFE_NAME.sub("_", raw_name)[:120] or f"evidence{suffix}"
    stored = f"{uuid.uuid4().hex[:12]}{suffix}"
    directory = _evidence_root() / str(task_id)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / stored).write_bytes(data)

    digest = hashlib.sha256(data).hexdigest()
    with connect() as conn:
        cursor = conn.execute(
            """INSERT INTO manual_evidence(task_id, item_id, filename, stored_name, size_bytes, sha256,
               note, uploaded_by, created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                task_id,
                payload.item_id,
                safe_name,
                stored,
                len(data),
                digest,
                payload.note.strip()[:300],
                session.username,
                now_iso(),
            ),
        )
        evidence_id = int(cursor.lastrowid)
    audit(
        session.user_id,
        session.username,
        "task_evidence_uploaded",
        client_ip_of(request),
        f"task={task_id} item={payload.item_id} file={safe_name} size={len(data)} sha256={digest[:12]}",
    )
    return {
        "ok": True,
        "evidence": {
            "id": evidence_id,
            "item_id": payload.item_id,
            "filename": safe_name,
            "size_bytes": len(data),
            "sha256": digest,
        },
    }


@router.get("/tasks/{task_id}/evidence/{evidence_id}")
def download_evidence(
    task_id: int,
    evidence_id: int,
    session: SessionContext = Depends(require_operator),
):
    task = _task_or_404(task_id)
    _assert_can_view(session, task)
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM manual_evidence WHERE id=? AND task_id=?", (evidence_id, task_id)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "证据文件不存在"})
    path = _evidence_root() / str(task_id) / str(row["stored_name"])
    if not path.is_file():
        raise HTTPException(status_code=410, detail={"code": "evidence_missing", "message": "证据文件已不在磁盘上"})
    return FileResponse(
        path,
        filename=str(row["filename"]),
        media_type="application/octet-stream",
        headers={"Cache-Control": "no-store"},
    )


def _collect_run_ids(task_id: int, task: dict[str, Any] | None = None) -> list[int]:
    """该任务关联的全部 run_id（task_runs 表 + 任务自身的 run_id），保序去重。"""
    row = task if task is not None else tasks.task_by_id(task_id)
    run_ids = [int(item["run_id"]) for item in tasks.task_runs(task_id)]
    if row and row.get("run_id"):
        run_ids.append(int(row["run_id"]))
    return list(dict.fromkeys(run_ids))


def _delete_task_rows(conn: Any, task_ids: list[int], run_ids: list[int]) -> None:
    """在**调用方的事务里**删除任务行与其 suite_runs（task_runs 随任务级联）。

    SQL 只有这一份：单删与批量删都走它，避免两处各写一套以后漂移。
    """
    if task_ids:
        placeholders = ",".join("?" * len(task_ids))
        conn.execute(f"DELETE FROM test_tasks WHERE id IN ({placeholders})", tuple(task_ids))
    for run_id in run_ids:
        conn.execute("DELETE FROM suite_runs WHERE id=?", (run_id,))


def _purge_evidence(task_id: int) -> None:
    """清理证据目录。磁盘操作，必须在事务提交之后调用。"""
    directory = _evidence_root() / str(task_id)
    if directory.is_dir():
        for child in directory.iterdir():
            child.unlink(missing_ok=True)
        directory.rmdir()


def _purge_task(task_id: int) -> list[int]:
    """删除单个任务及其 run 与证据，返回被删的 run_ids。

    不写审计、不判权限、不判运行中——这些由调用方负责（单删与批量删的规则不同）。
    """
    run_ids = _collect_run_ids(task_id)
    with connect() as conn:
        _delete_task_rows(conn, [task_id], run_ids)
    _purge_evidence(task_id)
    return run_ids


@router.delete("/tasks/{task_id}")
def delete_task(task_id: int, request: Request, session: SessionContext = Depends(require_admin)) -> dict:
    """删除**单个**任务：连同它的全部模型执行记录与证据目录。

    批量删除在 `bulk_delete_tasks`：只删非运行中任务；删除全部需要确认词 `DELETE`；
    逐条清理 run 与证据目录。两者的清理逻辑共用 `_delete_task_rows` / `_purge_evidence`，
    不各写一套。
    """
    require_csrf(request, session)
    task = _task_or_404(task_id)
    if tasks.is_running(task_id):
        raise HTTPException(status_code=409, detail={"code": "already_running", "message": "任务正在执行，不能删除"})
    run_ids = _purge_task(task_id)
    audit(
        session.user_id, session.username, "task_deleted", client_ip_of(request),
        f"task={task_id} runs={','.join(str(x) for x in run_ids)}",
    )
    return {"ok": True, "runs_deleted": run_ids}


@router.post("/tasks/bulk-delete")
def bulk_delete_tasks(
    payload: BulkDeletePayload, request: Request, session: SessionContext = Depends(require_admin)
) -> dict:
    """批量删除任务：选中删除，或删除全部（需确认词）。

    逐条判定的顺序是**刻意**的：先剔掉不存在/不属本人的（skipped_missing），
    再剔掉运行中的（skipped_running），剩下的才删。运行中的任务不报错、不中断整批——
    一条在跑不该让其余 199 条删不掉；但它们必须出现在 skipped_running 里，
    否则"删了 12 条"会让人以为全删了。

    `all` 模式不受 200 条上限约束：确认词 `DELETE` 就是它的门槛，而数量上限会与
    "全部"语义直接冲突（列表页只显示 50 条，用户看不到真实总数）。
    """
    require_csrf(request, session)
    is_admin = session.role == "admin"
    if payload.all:
        if payload.confirm != "DELETE":
            raise HTTPException(
                status_code=400,
                detail={"code": "confirm_required", "message": "删除全部任务需要输入确认词 DELETE"},
            )
        # 直接取全部 id，而不是走 list_tasks：后者把 limit 硬顶在 200，
        # "删除全部"在 >200 条时会被截断成"删前 200 条"，且不报错。
        with connect() as conn:
            if is_admin or session.user_id is None:
                rows = conn.execute("SELECT id FROM test_tasks ORDER BY id DESC").fetchall()
            else:
                rows = conn.execute(
                    "SELECT id FROM test_tasks WHERE user_id=? ORDER BY id DESC", (session.user_id,)
                ).fetchall()
        targets = [int(row["id"]) for row in rows]
    else:
        targets = list(dict.fromkeys(int(x) for x in (payload.task_ids or [])))
        if not targets:
            raise HTTPException(
                status_code=400, detail={"code": "empty_selection", "message": "未选择任何任务"}
            )

    # 数量上限**只约束显式列表**（防畸形请求体）。
    # `all` 不设上限：确认词 DELETE 已经是这个动作的守门人，再叠一个用户看不见的上限，
    # 只会制造"点了删除全部、输对了确认词、却因为库里有 201 条而删不掉"的死角——
    # 而列表页默认只显示 50 条，用户根本无从得知这个数字。
    if not payload.all and len(targets) > MAX_BULK_DELETE:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "too_many",
                "message": f"一次最多删除 {MAX_BULK_DELETE} 个任务，本次目标 {len(targets)} 个",
            },
        )

    deleted: list[int] = []
    skipped_running: list[int] = []
    skipped_missing: list[int] = []
    run_map: dict[int, list[int]] = {}
    for task_id in targets:
        row = tasks.task_by_id(task_id)
        if row is None or (not is_admin and row.get("user_id") != session.user_id):
            skipped_missing.append(task_id)
            continue
        if tasks.is_running(task_id):
            skipped_running.append(task_id)
            continue
        deleted.append(task_id)
        run_map[task_id] = _collect_run_ids(task_id, row)

    all_run_ids = [run_id for ids in run_map.values() for run_id in ids]
    with connect() as conn:
        _delete_task_rows(conn, deleted, all_run_ids)
    # 磁盘清理在事务提交之后：它不属于事务，失败也不该回滚已删的库记录
    for task_id in deleted:
        _purge_evidence(task_id)

    mode = "all" if payload.all else "selected"
    listed = ",".join(str(x) for x in deleted[:20]) + ("…" if len(deleted) > 20 else "")
    audit(
        session.user_id,
        session.username,
        "task_bulk_deleted",
        client_ip_of(request),
        f"mode={mode} count={len(deleted)} running_skipped={len(skipped_running)} missing={len(skipped_missing)} ids={listed}",
    )
    return {
        "ok": True,
        "deleted": deleted,
        "skipped_running": skipped_running,
        "skipped_missing": skipped_missing,
        "runs_deleted": len(all_run_ids),
    }
