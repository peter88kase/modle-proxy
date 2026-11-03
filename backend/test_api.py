"""Model testing, streaming proxy, acceptance suite and record export."""

from __future__ import annotations

import asyncio
import csv
import io
import json
from dataclasses import replace
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field

from .adapters.base import ADAPTERS, CallSpec, get_adapter
from .config import settings
from .db import all_runtime_settings, audit, connect, now_iso
from .deps import client_ip_of, require_admin, require_csrf, require_operator
from .netguard import TargetError, validate_url
from .run_records import case_status as run_case_status
from .run_records import record_case_item, upsert_item
from .security import SessionContext, redact_text
from .standard_checks import CHECKS, run_auto_checks
from .standards import (
    FAIL,
    NOT_TESTED,
    PASS,
    PENDING,
    conclusion,
    get_version,
    load_run_items,
    resolve_entries,
)
from .suite import SuiteConfig, run_suite
from .upstream import execute, list_models

router = APIRouter(prefix="/api", tags=["testing"])

_run_semaphore = asyncio.Semaphore(max(1, settings.model_max_concurrency))

# 同一 case_id 在双链路下会出现两次，合并时取“最差”状态：
# 任一条链路不通过即为不通过，其次待确认、未测试，全部通过才是通过。
_CASE_STATUS_RANK = {PASS: 0, NOT_TESTED: 1, PENDING: 2, FAIL: 3}


def _case_status(result: str, execution: str) -> str:
    """套件结果 → 单项状态。委托给 run_records，避免两份映射口径各自漂移。"""
    return run_case_status(result, execution)


def _record_case_item(
    conn: Any, run_id: int, data: dict[str, Any], standard: Any, username: str
) -> None:
    """把第一章用例结果写入 run_items。

    这里**只做转发**：真正的写入口在 `run_records.record_case_item`。过去这个函数
    自己拼了一版 SQL，于是同一个 case_id 经旧 SSE 接口与后台任务写入时，
    `blocker_reason` / `na_basis` / `item_key` 的处理不一样——同一个批次里
    出现两种记录格式，报告只能按最保守的一版解释。
    """
    record_case_item(conn, run_id, data, standard, username)


class RunPayload(BaseModel):
    provider_id: str = "custom"
    adapter: str = "openai"
    link: Literal["direct", "forward"] = "direct"
    base_url: str = Field(default="", max_length=512)
    model: str = Field(min_length=1, max_length=200)
    auth_style: str = Field(default="", max_length=32)
    api_key: str = Field(default="", max_length=4096, repr=False)
    api_secret: str = Field(default="", max_length=4096, repr=False)
    system: str = Field(default="", max_length=8000)
    prompt: str = Field(default="只回复 CONNECT_OK", max_length=20000)
    max_tokens: int = Field(default=64, ge=1, le=32768)
    temperature: float | None = Field(default=0.2, ge=0, le=2)
    top_p: float | None = Field(default=None, ge=0, le=1)
    stream: bool = False
    stream_usage: bool = False
    total_timeout: float = Field(default=60, ge=3, le=300)
    connect_timeout: float = Field(default=10, ge=1, le=60)
    first_token_timeout: float = Field(default=30, ge=3, le=300)


class SuitePayload(RunPayload):
    links: list[Literal["direct", "forward"]] = Field(default_factory=lambda: ["direct"])
    forward_base_url: str = Field(default="", max_length=512)
    forward_model: str = Field(default="", max_length=200)
    forward_api_key: str = Field(default="", max_length=4096, repr=False)
    repeat: int = Field(default=3, ge=1, le=5)
    #: 相邻两次上游请求的最小间隔（秒）。0 = 不限速；None = 用部署默认值。
    request_interval: float | None = Field(default=None, ge=0, le=30)
    unreachable_url: str = Field(default="", max_length=512)
    mock_no_content_url: str = Field(default="", max_length=512)
    mock_heartbeat_url: str = Field(default="", max_length=512)
    # 绑定第 2～4 章测试标准版本；为空则该批次不产生标准判定，也不能导出 PDF 报告
    standard_version_id: int | None = Field(default=None, ge=1)


class ModelsPayload(BaseModel):
    provider_id: str = ""
    base_url: str = Field(min_length=1, max_length=512)
    auth_style: str = Field(default="", max_length=32)
    adapter: str = "openai"
    api_key: str = Field(default="", max_length=4096, repr=False)


def _sse(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode("utf-8")


def _provider(provider_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM providers WHERE id=?", (provider_id,)).fetchone()
    if row is None:
        return None
    data = dict(row)
    try:
        data["protocols"] = json.loads(data.get("protocols") or "[]")
    except ValueError:
        data["protocols"] = []
    return data


def _resolve(payload: RunPayload) -> tuple[Any, str, str, str]:
    adapter = ADAPTERS.get(payload.adapter)
    if adapter is None:
        raise HTTPException(status_code=400, detail={"code": "unknown_adapter", "message": "未知的适配器"})
    provider = _provider(payload.provider_id) or {}
    base_url = payload.base_url.strip()
    if not base_url:
        base_url = (provider.get("forward_base_url") if payload.link == "forward" else provider.get("direct_base_url")) or ""
    if not base_url:
        raise HTTPException(status_code=400, detail={"code": "missing_endpoint", "message": "请填写接口地址（Endpoint）"})
    model = payload.model.strip()
    if not model:
        raise HTTPException(status_code=400, detail={"code": "missing_model", "message": "请填写模型标识"})
    return adapter, base_url, model, payload.api_key


def _spec(adapter, payload: RunPayload, base_url: str, model: str, key: str, stream: bool) -> CallSpec:
    return CallSpec(
        base_url=base_url,
        model=model,
        api_key=key,
        api_secret=payload.api_secret,
        auth_style=payload.auth_style,
        system=payload.system,
        prompt=payload.prompt,
        max_tokens=payload.max_tokens,
        temperature=payload.temperature,
        top_p=payload.top_p,
        stream=stream,
        stream_usage=payload.stream_usage,
    )


@router.get("/meta")
def meta(session: SessionContext = Depends(require_operator)) -> dict:
    return {
        "adapters": [
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
        ],
        "limits": {
            "model_total_timeout": settings.model_total_timeout,
            "model_first_token_timeout": settings.model_first_token_timeout,
            "model_connect_timeout": settings.model_connect_timeout,
            "model_max_concurrency": settings.model_max_concurrency,
            "model_max_body_bytes": settings.model_max_body_bytes,
            "allow_private_upstream": settings.allow_private_upstream,
            "shell_enabled": settings.shell_enabled,
        },
        "runtime_settings": all_runtime_settings(),
        "server_time": now_iso(),
    }


@router.post("/test/run")
async def run_once(payload: RunPayload, request: Request, session: SessionContext = Depends(require_operator)) -> dict:
    require_csrf(request, session)
    adapter, base_url, model, key = _resolve(payload)
    try:
        await asyncio.wait_for(_run_semaphore.acquire(), timeout=10)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=429, detail={"code": "busy", "message": "并发测试已满，请稍后重试"})
    try:
        outcome = await execute(
            adapter,
            _spec(adapter, payload, base_url, model, key, payload.stream),
            total_timeout=payload.total_timeout,
            connect_timeout=payload.connect_timeout,
            first_token_timeout=payload.first_token_timeout,
            max_bytes=settings.model_max_body_bytes,
        )
    finally:
        _run_semaphore.release()
        payload.api_key = ""
        payload.api_secret = ""

    audit(
        session.user_id,
        session.username,
        "model_test",
        client_ip_of(request),
        f"provider={payload.provider_id} model={model} link={payload.link} status={outcome.http_status} ok={outcome.ok}",
    )
    data = outcome.summary()
    data["text"] = outcome.text
    data["provider_id"] = payload.provider_id
    data["model"] = model
    data["link"] = payload.link
    return data


@router.post("/test/stream")
async def run_stream(payload: RunPayload, request: Request, session: SessionContext = Depends(require_operator)):
    require_csrf(request, session)
    adapter, base_url, model, key = _resolve(payload)

    async def generator():
        acquired = False
        task: asyncio.Task | None = None
        queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue()

        async def on_event(kind: str, data: dict[str, Any]) -> None:
            await queue.put((kind, data))

        try:
            await asyncio.wait_for(_run_semaphore.acquire(), timeout=10)
            acquired = True
        except asyncio.TimeoutError:
            yield _sse("error", {"message": "并发测试已满，请稍后重试"})
            return

        try:
            yield _sse(
                "start",
                {
                    "provider_id": payload.provider_id,
                    "model": model,
                    "link": payload.link,
                    "adapter": adapter.id,
                    "ttft_budget_ms": int(payload.first_token_timeout * 1000),
                    "total_budget_ms": int(payload.total_timeout * 1000),
                },
            )
            task = asyncio.create_task(
                execute(
                    adapter,
                    _spec(adapter, payload, base_url, model, key, stream=True),
                    total_timeout=payload.total_timeout,
                    connect_timeout=payload.connect_timeout,
                    first_token_timeout=payload.first_token_timeout,
                    max_bytes=settings.model_max_body_bytes,
                    on_event=on_event,
                )
            )
            last_ping = asyncio.get_event_loop().time()
            while True:
                if task.done() and queue.empty():
                    break
                try:
                    kind, data = await asyncio.wait_for(queue.get(), timeout=0.25)
                    yield _sse(kind, data)
                except asyncio.TimeoutError:
                    now = asyncio.get_event_loop().time()
                    if now - last_ping > 15:
                        last_ping = now
                        yield b": keep-alive\n\n"
            outcome = await task
            if outcome.error_code and not outcome.text:
                yield _sse("error", {"code": outcome.error_code, "message": redact_text(outcome.error_message, 300)})
            yield _sse("done", outcome.summary())
            audit(
                session.user_id,
                session.username,
                "model_stream_test",
                client_ip_of(request),
                f"provider={payload.provider_id} model={model} status={outcome.http_status} ttft={outcome.ttft_ms}",
            )
        except asyncio.CancelledError:
            if task and not task.done():
                task.cancel()
            raise
        except Exception as exc:  # noqa: BLE001 - surface a safe message, never a stack trace
            yield _sse("error", {"code": "internal_error", "message": redact_text(str(exc), 200)})
        finally:
            if task and not task.done():
                task.cancel()
            if acquired:
                _run_semaphore.release()
            payload.api_key = ""
            payload.api_secret = ""

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@router.post("/suite/run")
async def run_suite_endpoint(payload: SuitePayload, request: Request, session: SessionContext = Depends(require_operator)):
    require_csrf(request, session)
    adapter = ADAPTERS.get(payload.adapter)
    if adapter is None:
        raise HTTPException(status_code=400, detail={"code": "unknown_adapter", "message": "未知的适配器"})
    model = payload.model.strip()
    if not model:
        raise HTTPException(status_code=400, detail={"code": "missing_model", "message": "请填写模型标识"})
    provider = _provider(payload.provider_id) or {}
    links = list(dict.fromkeys(payload.links))
    if not links:
        raise HTTPException(status_code=400, detail={"code": "missing_link", "message": "请至少选择一条测试链路"})

    direct_base = payload.base_url.strip() or provider.get("direct_base_url", "")
    forward_base = payload.forward_base_url.strip() or provider.get("forward_base_url", "")
    if "direct" in links and not direct_base:
        raise HTTPException(status_code=400, detail={"code": "missing_endpoint", "message": "未配置上游直连地址"})
    if "forward" in links and not forward_base:
        raise HTTPException(status_code=400, detail={"code": "missing_forward", "message": "未配置转发链路地址"})

    forward_model = payload.forward_model.strip() or model
    try:
        host = validate_url(direct_base or forward_base).host
    except TargetError:
        host = ""

    standard = None
    if payload.standard_version_id:
        standard = get_version(payload.standard_version_id)
        if standard is None:
            raise HTTPException(status_code=404, detail={"code": "standard_missing", "message": "测试标准版本不存在"})

    with connect() as conn:
        cursor = conn.execute(
            """INSERT INTO suite_runs(created_at, user_id, provider_id, provider_name, adapter, link, model,
               endpoint_host, passed, failed, skipped, note,
               standard_version_id, standard_version, standard_checksum, conclusion)
               VALUES (?,?,?,?,?,?,?,?,0,0,0,'',?,?,?,'')""",
            (
                now_iso(),
                session.user_id,
                payload.provider_id,
                provider.get("name", payload.provider_id),
                adapter.id,
                "+".join(links),
                model,
                host,
                standard.id if standard else None,
                standard.version if standard else "",
                standard.checksum if standard else "",
            ),
        )
        run_id = cursor.lastrowid

    cfg = SuiteConfig(
        provider_id=payload.provider_id,
        provider_name=provider.get("name", payload.provider_id),
        adapter=adapter.id,
        model=model,
        links=links,
        direct_base_url=direct_base,
        forward_base_url=forward_base,
        forward_model=forward_model,
        api_key=payload.api_key,
        forward_api_key=payload.forward_api_key or payload.api_key,
        api_secret=payload.api_secret,
        auth_style=payload.auth_style,
        prompt=payload.prompt,
        system=payload.system,
        max_tokens=payload.max_tokens,
        temperature=payload.temperature,
        stream_usage=payload.stream_usage,
        repeat=payload.repeat,
        total_timeout=payload.total_timeout,
        first_token_timeout=payload.first_token_timeout,
        connect_timeout=payload.connect_timeout,
        request_interval=payload.request_interval,
        unreachable_url=payload.unreachable_url,
        mock_no_content_url=payload.mock_no_content_url,
        mock_heartbeat_url=payload.mock_heartbeat_url,
        user_id=session.user_id,
        username=session.username,
    )
    # 自动标准检查在套件结束后仍需一次真实请求，凭据在此单独持有一份，
    # 由 run_suite 结束时的 cfg.wipe() 之外的 finally 统一清零。
    check_cfg = replace(cfg)

    async def generator():
        summary = {"passed": 0, "failed": 0, "skipped": 0}
        # The suite engine reports through a callback; a queue lets the SSE
        # generator stream each case to the browser as soon as it is judged.
        queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue()

        async def emit(kind: str, data: dict[str, Any]) -> None:
            if kind == "case":
                with connect() as conn:
                    conn.execute(
                        """INSERT INTO suite_cases(run_id, case_id, title, result, evidence, http_status,
                           latency_ms, created_at) VALUES (?,?,?,?,?,?,?,?)""",
                        (
                            run_id,
                            data.get("case_id", ""),
                            data.get("title", ""),
                            data.get("result", ""),
                            data.get("evidence", ""),
                            data.get("http_status"),
                            data.get("latency_ms"),
                            now_iso(),
                        ),
                    )
                    _record_case_item(conn, run_id, data, standard, session.username)
            elif kind == "item":
                with connect() as conn:
                    # 与后台任务共用同一写入口：blocked 必须带枚举原因、
                    # 自动 NA 必须归一成 pending、item_key 必须落库。
                    upsert_item(conn, run_id, data, session.username, standard)
            await queue.put((kind, data))

        task = asyncio.create_task(run_suite(cfg, emit))
        try:
            yield _sse(
                "start",
                {
                    "run_id": run_id,
                    "provider": provider.get("name", payload.provider_id),
                    "model": model,
                    "links": links,
                    "repeat": payload.repeat,
                    "adapter": adapter.id,
                },
            )

            while True:
                if task.done() and queue.empty():
                    break
                try:
                    kind, data = await asyncio.wait_for(queue.get(), timeout=0.3)
                except asyncio.TimeoutError:
                    continue
                yield _sse(kind, data)

            result = await task
            summary = {
                "passed": result.get("passed", 0),
                "failed": result.get("failed", 0),
                "skipped": result.get("skipped", 0),
            }
            with connect() as conn:
                conn.execute(
                    "UPDATE suite_runs SET passed=?, failed=?, skipped=? WHERE id=?",
                    (summary["passed"], summary["failed"], summary["skipped"], run_id),
                )

            # 第 2～4 章：仅执行平台能真实判定的自动项，其余保留人工确认入口。
            # 第一章的 auto 项由 suite_cases 直接产出结果（auto_check 为空），不在此重复执行。
            if standard is not None:
                auto_items = [
                    item
                    for item in standard.ordered_items()
                    if item.enabled and item.execution == "auto" and item.auto_check in CHECKS
                ]
                if auto_items:
                    yield _sse("items_start", {"run_id": run_id, "count": len(auto_items)})
                    await run_auto_checks(check_cfg, auto_items, emit)
                    # 自动检查是串行 await 的，其事件先进队列，这里统一排空后再发结论
                    while not queue.empty():
                        kind, data = queue.get_nowait()
                        yield _sse(kind, data)
                entries = resolve_entries(standard, load_run_items(run_id))
                verdict = conclusion(entries)
                with connect() as conn:
                    conn.execute("UPDATE suite_runs SET conclusion=? WHERE id=?", (verdict["verdict"], run_id))
                yield _sse(
                    "conclusion",
                    {
                        "run_id": run_id,
                        "verdict": verdict["verdict"],
                        "reason": verdict["reason"],
                        "counts": verdict["counts"],
                        "standard_version": standard.version,
                    },
                )
                summary["verdict"] = verdict["verdict"]

            yield _sse("done", {"run_id": run_id, **summary})
            audit(
                session.user_id,
                session.username,
                "suite_run",
                client_ip_of(request),
                f"run={run_id} provider={payload.provider_id} model={model} "
                f"pass={summary['passed']} fail={summary['failed']} skip={summary['skipped']}",
            )
        except asyncio.CancelledError:
            task.cancel()
            with connect() as conn:
                conn.execute("UPDATE suite_runs SET note=? WHERE id=?", ("客户端中断，结果不完整", run_id))
            raise
        except Exception as exc:  # noqa: BLE001
            yield _sse("error", {"code": "suite_failed", "message": redact_text(str(exc), 200)})
        finally:
            if not task.done():
                task.cancel()
            payload.api_key = ""
            payload.api_secret = ""
            payload.forward_api_key = ""
            check_cfg.wipe()

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.post("/models/list")
async def fetch_models(payload: ModelsPayload, request: Request, session: SessionContext = Depends(require_operator)) -> dict:
    require_csrf(request, session)
    adapter = ADAPTERS.get(payload.adapter)
    if adapter is None:
        raise HTTPException(status_code=400, detail={"code": "unknown_adapter", "message": "未知的适配器"})
    try:
        models = await list_models(adapter, payload.base_url, payload.api_key, payload.auth_style)
    except TargetError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message})
    except Exception as exc:  # noqa: BLE001 - never leak headers or keys
        raise HTTPException(status_code=502, detail={"code": "upstream_error", "message": redact_text(str(exc), 200)})
    finally:
        payload.api_key = ""
    return {"items": models, "source": "upstream", "count": len(models)}


@router.get("/suite/runs")
def list_runs(limit: int = 30, session: SessionContext = Depends(require_operator)) -> dict:
    limit = max(1, min(limit, 200))
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM suite_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return {"items": [dict(row) for row in rows]}


@router.get("/suite/runs/{run_id}")
def get_run(run_id: int, session: SessionContext = Depends(require_operator)) -> dict:
    with connect() as conn:
        run = conn.execute("SELECT * FROM suite_runs WHERE id=?", (run_id,)).fetchone()
        if run is None:
            raise HTTPException(status_code=404, detail={"code": "not_found", "message": "记录不存在"})
        cases = conn.execute(
            "SELECT case_id, title, result, evidence, http_status, latency_ms FROM suite_cases WHERE run_id=? ORDER BY id",
            (run_id,),
        ).fetchall()
    return {"run": dict(run), "cases": [dict(case) for case in cases]}


@router.delete("/suite/runs/{run_id}")
def delete_run(run_id: int, request: Request, session: SessionContext = Depends(require_admin)) -> dict:
    require_csrf(request, session)
    with connect() as conn:
        conn.execute("DELETE FROM suite_runs WHERE id=?", (run_id,))
    audit(session.user_id, session.username, "suite_run_deleted", client_ip_of(request), f"run={run_id}")
    return {"ok": True}


@router.get("/suite/runs/{run_id}/export")
def export_run(run_id: int, format: str = "md", session: SessionContext = Depends(require_operator)):
    with connect() as conn:
        run = conn.execute("SELECT * FROM suite_runs WHERE id=?", (run_id,)).fetchone()
        if run is None:
            raise HTTPException(status_code=404, detail={"code": "not_found", "message": "记录不存在"})
        cases = conn.execute(
            "SELECT case_id, title, result, evidence, http_status, latency_ms FROM suite_cases WHERE run_id=? ORDER BY id",
            (run_id,),
        ).fetchall()

    if format == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["用例编号", "检查项", "结果", "证据", "HTTP 状态", "耗时(ms)"])
        for case in cases:
            writer.writerow([case["case_id"], case["title"], case["result"], case["evidence"], case["http_status"] or "", case["latency_ms"] or ""])
        content = "\ufeff" + buffer.getvalue()
        return Response(
            content=content.encode("utf-8"),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="suite-run-{run_id}.csv"'},
        )

    lines = [
        f"# 供应商接入测试记录（记录 #{run_id}）",
        "",
        f"- 供应商/渠道：{run['provider_name']}（{run['provider_id']}）",
        f"- 适配器/协议：{run['adapter']}",
        f"- 模型 ID：{run['model']}",
        f"- 测试链路：{' + '.join({'direct': '上游直连', 'forward': '转发链路'}.get(part, part) for part in str(run['link']).split('+'))}",
        f"- 端点主机：{run['endpoint_host'] or '未记录'}",
        f"- 执行时间：{run['created_at']}",
        f"- 汇总：PASS {run['passed']} / FAIL {run['failed']} / SKIP {run['skipped']}",
        f"- 备注：{run['note'] or '无'}",
        "",
        "| 用例编号 | 检查项 | 结果 | 证据 | HTTP | 耗时(ms) |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for case in cases:
        evidence = (case["evidence"] or "").replace("|", "\\|")
        lines.append(
            f"| {case['case_id']} | {case['title']} | {case['result']} | {evidence} | {case['http_status'] or '-'} | {case['latency_ms'] or '-'} |"
        )
    lines += [
        "",
        "> 说明：本记录由平台自动生成，仅包含请求元数据与用例判定，不含任何 AK/SK、API Key、提示词正文或模型响应正文。",
    ]
    return Response(
        content="\n".join(lines).encode("utf-8"),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="suite-run-{run_id}.md"'},
    )
