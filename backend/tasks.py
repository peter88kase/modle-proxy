"""供应商验收任务：后台执行引擎、状态机与判定汇总。

设计要点
--------
* **任务与执行记录分离**：``test_tasks`` 保存任务生命周期（状态、阶段、进度、
  结论），``suite_runs`` 保存它产生的执行记录，报告与记录页继续复用既有代码。
* **凭证只在内存里**：API Key 仅存在于 ``TaskRuntime.cfg`` 与 ``api_key`` 字段中，
  任务完成/取消/异常时立即清零；数据库、日志、报告里只有脱敏标识。
* **预算硬边界**：每次请求先经过 ``budget.take_request()``，超出次数或时长后
  不再发出请求，剩余用例记为“未测试/阻塞”，不会继续产生费用。
* **判定唯一来源**：任务结束、人工确认、单用例重测之后都调用同一套
  ``resolve_entries`` + ``conclusion``，页面与 PDF 不允许各自计算。
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field, replace
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from .budget import Budget, reset_budget, set_budget
from .config import settings
from .db import connect, now_iso
from .netguard import TargetError, validate_url
from .run_records import record_case_item, upsert_item
from .security import redact_text
from .standard_checks import CHECKS, run_auto_checks
from .standards import (
    BLOCKED,
    CRITICAL_FIRST_CHAPTER,
    FAIL,
    NOT_TESTED,
    PASS,
    PENDING,
    PRE_GATE_IDS,
    VERDICT_FAIL,
    VERDICT_PARTIAL,
    VERDICT_PASS,
    VERDICT_UNDECIDED,
    Version,
    conclusion,
    get_version,
    load_run_items,
    resolve_entries,
)
from .suite import SuiteConfig, run_suite

# --- 任务状态 ---------------------------------------------------------------
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_INTERRUPTED = "interrupted"

TASK_STATUS_LABELS = {
    STATUS_QUEUED: "排队中",
    STATUS_RUNNING: "执行中",
    STATUS_SUCCEEDED: "已完成",
    STATUS_FAILED: "执行失败",
    STATUS_CANCELLED: "已取消",
    STATUS_INTERRUPTED: "已中断",
}

# --- 执行阶段 ---------------------------------------------------------------
PHASE_LABELS = {
    "gate": "前置必测（连通性 / 缓存命中率 / 延时）",
    "ch1": "第一章 连通性与鉴权",
    "ch2": "第二章 接口兼容性",
    "ch3": "第三章 缓存正确性",
    "ch4": "第四章 模型与能力真实性",
    "final": "汇总判定",
}

# 第一章里决定“后续章节还能不能跑”的关键项：只要没有任何一项通过，
# 说明端点根本调不通，后续自动项一律记“阻塞”，避免无意义地烧预算。
# 关键项清单只有一处定义（standards.CRITICAL_FIRST_CHAPTER），报告与门禁共用。

# 150 → 200：前置必测固定消耗 28 次真实请求（2 连通 + 6 缓存 + 20 延时），
# 沿用旧上限会把第 2～4 章挤成“未测试”，把预算不足伪装成供应商问题。
DEFAULT_BUDGET = {"max_requests": 200, "max_seconds": 900}

logger = logging.getLogger("bedrock.tasks")


class TaskError(ValueError):
    """用户可见的任务错误（带错误码）。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ModelRun:
    """一个任务里的一个模型：模型 ID、执行配置与它独占的执行记录。"""

    model: str
    cfg: SuiteConfig
    run_id: int


@dataclass
class TaskRuntime:
    task: asyncio.Task | None
    entries: list[ModelRun]
    budget: dict[str, Any]
    cancel_reason: str = ""
    current_model: str = ""
    #: 每个模型跑完后的预算快照，任务收尾时汇总成一份可读预算。
    snapshots: list[dict[str, Any]] = field(default_factory=list)


# 任务 id -> 运行态。API Key 只在这里和 cfg 里，进程内、内存中。
_RUNTIME: dict[int, TaskRuntime] = {}


def active_task_ids() -> list[int]:
    return sorted(_RUNTIME)


def is_running(task_id: int) -> bool:
    return task_id in _RUNTIME


# --------------------------------------------------------------------------
# 读取
# --------------------------------------------------------------------------
def _loads(raw: str | None, fallback: Any) -> Any:
    if not raw:
        return fallback
    try:
        value = json.loads(raw)
    except ValueError:
        return fallback
    return value if isinstance(value, type(fallback)) else fallback


def task_by_id(task_id: int) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM test_tasks WHERE id=?", (task_id,)).fetchone()
    return _expand(row) if row else None


def task_by_run(run_id: int) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM test_tasks WHERE run_id=? ORDER BY id DESC LIMIT 1", (run_id,)
        ).fetchone()
    return _expand(row) if row else None


def _expand(row: Any) -> dict[str, Any]:
    data = dict(row)
    data["budget"] = _loads(data.get("budget"), {})
    data["options"] = _loads(data.get("options"), {})
    data["counts"] = _loads(data.get("counts"), {})
    data["models"] = _loads(data.get("models"), [])
    data["status_label"] = TASK_STATUS_LABELS.get(str(data.get("status")), str(data.get("status")))
    data["phase_label"] = PHASE_LABELS.get(str(data.get("phase")), str(data.get("phase")))
    data["live"] = is_running(int(data["id"]))
    return data


def batch_tasks(batch_id: str) -> list[dict[str, Any]]:
    """同一批次（= 一次提交里的多个模型）的全部任务，按 id 升序。

    **同一个模型可能有多条**（重测会新建任务并继承 batch_id），
    调用方应自己按 model 取最新一条，别在这里替它猜。
    """
    key = (batch_id or "").strip()
    if not key:
        return []
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM test_tasks WHERE batch_id=? ORDER BY id ASC", (key,)
        ).fetchall()
    return [_expand(row) for row in rows]


def latest_per_model(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """批次里每个模型只留**最新一次**任务（重测过的取重测那条）。"""
    latest: dict[str, dict[str, Any]] = {}
    for task in tasks:
        latest[str(task.get("model") or "")] = task
    return list(latest.values())


# --------------------------------------------------------------------------
# 任务内模型明细（task_runs）
# --------------------------------------------------------------------------
def _expand_run(row: Any) -> dict[str, Any]:
    data = dict(row)
    data["counts"] = _loads(data.get("counts"), {})
    data["metrics"] = _loads(data.get("metrics"), {})
    data["status_label"] = TASK_STATUS_LABELS.get(str(data.get("status")), str(data.get("status")))
    return data


def add_task_run(task_id: int, model: str, run_id: int) -> None:
    with connect() as conn:
        conn.execute(
            """INSERT INTO task_runs(task_id, model, run_id, status, created_at)
               VALUES (?,?,?,?,?)
               ON CONFLICT(task_id, model) DO UPDATE SET run_id=excluded.run_id""",
            (task_id, model, run_id, STATUS_QUEUED, now_iso()),
        )


def task_runs(task_id: int) -> list[dict[str, Any]]:
    """任务内的模型明细，按创建顺序。历史任务没有明细时返回空列表。"""
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM task_runs WHERE task_id=? ORDER BY rowid", (task_id,)
        ).fetchall()
    return [_expand_run(row) for row in rows]


def task_run_for(task_id: int, model: str = "") -> dict[str, Any] | None:
    """取某个模型的明细；不指定模型时取第一个（历史任务等价于 task.run_id）。"""
    with connect() as conn:
        if model:
            row = conn.execute(
                "SELECT * FROM task_runs WHERE task_id=? AND model=?", (task_id, model)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM task_runs WHERE task_id=? ORDER BY rowid LIMIT 1", (task_id,)
            ).fetchone()
    return _expand_run(row) if row else None


def update_task_run(task_id: int, model: str, **fields: Any) -> None:
    if not fields:
        return
    columns = ", ".join(f"{name}=?" for name in fields)
    values = (*fields.values(), task_id, model)

    def action() -> None:
        with connect() as conn:
            conn.execute(f"UPDATE task_runs SET {columns} WHERE task_id=? AND model=?", values)

    _retry_write(action)


def task_model_list(task: dict[str, Any]) -> list[str]:
    """任务声明的模型列表；历史任务没有 models 字段时回退到单列 model。"""
    models = task.get("models")
    if isinstance(models, list):
        cleaned = [str(m).strip() for m in models if str(m).strip()]
        if cleaned:
            return cleaned
    single = str(task.get("model") or "").strip()
    return [single] if single else []



def list_tasks(user_id: int | None, is_admin: bool, limit: int = 50) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 200))
    with connect() as conn:
        if is_admin or user_id is None:
            rows = conn.execute("SELECT * FROM test_tasks ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM test_tasks WHERE user_id=? ORDER BY id DESC LIMIT ?", (user_id, limit)
            ).fetchall()
    return [_expand(row) for row in rows]


def evidence_for(task_id: int, item_id: str | None = None) -> list[dict[str, Any]]:
    with connect() as conn:
        if item_id:
            rows = conn.execute(
                "SELECT id, item_id, filename, size_bytes, sha256, note, uploaded_by, created_at "
                "FROM manual_evidence WHERE task_id=? AND item_id=? ORDER BY id",
                (task_id, item_id),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, item_id, filename, size_bytes, sha256, note, uploaded_by, created_at "
                "FROM manual_evidence WHERE task_id=? ORDER BY item_id, id",
                (task_id,),
            ).fetchall()
    return [dict(row) for row in rows]


def retest_history(task_id: int) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM retest_log WHERE task_id=? ORDER BY id DESC LIMIT 200", (task_id,)
        ).fetchall()
    return [dict(row) for row in rows]


# --------------------------------------------------------------------------
# 创建 / 启动
# --------------------------------------------------------------------------
def sanitize_endpoint(url: str) -> str:
    """去掉 URL 里的 userinfo、query 与 fragment，只保留 scheme/host/port/path。

    用来持久化“测试的 API 地址标识”。query 里可能带 token，因此不保存。
    """
    text = (url or "").strip()
    if not text:
        return ""
    parts = urlsplit(text)
    host = parts.hostname or ""
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def create_task(
    *,
    user_id: int,
    username: str,
    name: str,
    provider_id: str,
    adapter: str,
    model: str,
    base_url: str,
    standard: Version | None,
    options: dict[str, Any],
    budget: dict[str, Any] | None = None,
    parent_task_id: int | None = None,
    attempt: int = 1,
    batch_id: str = "",
    models: list[str] | None = None,
) -> int:
    """Insert a task row (no credentials) and return its id.

    ``models`` 是多模型任务的完整清单（顺序即执行顺序），``model`` 保留为首个模型，
    供历史接口与旧数据读取；两者不一致时以 ``models`` 为准。
    """
    try:
        target = validate_url(base_url)
    except TargetError as exc:
        raise TaskError(exc.code, exc.message) from exc
    except Exception as exc:  # noqa: BLE001 - 参数错误也要给出可读提示
        raise TaskError("invalid_endpoint", f"接口地址不合法：{redact_text(str(exc), 120)}") from exc

    payload = dict(options)
    payload["base_url"] = sanitize_endpoint(base_url)
    budget_payload = {**DEFAULT_BUDGET, **(budget or {})}
    model_list = list(dict.fromkeys([m.strip() for m in (models or [model]) if m.strip()])) or [model]
    with connect() as conn:
        cursor = conn.execute(
            """INSERT INTO test_tasks(
                 created_at, user_id, username, name, provider_id, adapter, model,
                 endpoint_host, endpoint_masked, link, standard_version_id, standard_version,
                 standard_checksum, status, phase, progress_done, progress_total, counts,
                 conclusion, stop_reason, run_id, parent_task_id, batch_id, attempt, budget,
                 options, error, models)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,'{}','','',NULL,?,?,?,?,?,'',?)""",
            (
                now_iso(),
                user_id,
                username,
                name.strip()[:120] or f"{adapter}:{model}",
                provider_id,
                adapter,
                model,
                target.host,
                sanitize_endpoint(base_url),
                "+".join(options.get("links") or ["direct"]),
                standard.id if standard else None,
                standard.version if standard else "",
                standard.checksum if standard else "",
                STATUS_QUEUED,
                "ch1",
                parent_task_id,
                batch_id,
                attempt,
                json.dumps(budget_payload, ensure_ascii=False),
                json.dumps(payload, ensure_ascii=False),
                json.dumps(model_list, ensure_ascii=False),
            ),
        )
        return int(cursor.lastrowid)


def build_suite_config(task: dict[str, Any], secret: str, forward_secret: str = "") -> SuiteConfig:
    options = task.get("options") or {}
    links = options.get("links") or ["direct"]
    return SuiteConfig(
        provider_id=str(task.get("provider_id") or "custom"),
        provider_name=str(task.get("name") or ""),
        adapter=str(task["adapter"]),
        model=str(task["model"]),
        links=list(links),
        direct_base_url=str(options.get("base_url") or ""),
        forward_base_url=str(options.get("forward_base_url") or ""),
        forward_model=str(options.get("forward_model") or task["model"]),
        api_key=secret,
        forward_api_key=forward_secret or secret,
        api_secret="",
        auth_style=str(options.get("auth_style") or ""),
        api_version=str(options.get("api_version") or ""),
        version_in_body=bool(options.get("version_in_body")),
        prompt=str(options.get("prompt") or "只回复 CONNECT_OK"),
        system=str(options.get("system") or ""),
        max_tokens=int(options.get("max_tokens") or 64),
        temperature=options.get("temperature", 0.2),
        stream_usage=bool(options.get("stream_usage")),
        repeat=int(options.get("repeat") or 3),
        total_timeout=float(options.get("total_timeout") or 60),
        first_token_timeout=float(options.get("first_token_timeout") or 30),
        connect_timeout=float(options.get("connect_timeout") or 10),
        # 0 是合法值（不限速），所以不能用 `or` 兜底——那会把 0 变成默认值；
        # None 继续留空，交给 settings.model_request_interval 兜底。
        request_interval=(
            None if options.get("request_interval") is None else float(options["request_interval"])
        ),
        unreachable_url=str(options.get("unreachable_url") or ""),
        mock_no_content_url=str(options.get("mock_no_content_url") or ""),
        mock_heartbeat_url=str(options.get("mock_heartbeat_url") or ""),
        user_id=task.get("user_id"),
        username=str(task.get("username") or ""),
    )


def _max_running() -> int:
    """并发执行上限。多模型批量提交时用它决定"立刻跑"还是"排队"。"""
    return max(1, min(2, int(settings.model_max_concurrency)))


#: 排队等待执行的任务（FIFO）。一个任务内的多个模型在任务内部顺序执行，
#: 任务之间仍按并发上限排队——网关按 RPM 限流，并发打过去只会让 429 污染判定。
_PENDING: list[tuple[int, list[ModelRun], dict[str, Any]]] = []


def _spawn(task_id: int, entries: list[ModelRun], budget_payload: dict[str, Any]) -> None:
    runtime = TaskRuntime(task=None, entries=entries, budget=budget_payload)
    _RUNTIME[task_id] = runtime
    runtime.task = asyncio.create_task(_execute(task_id, runtime))


def _drain_pending() -> None:
    """一个任务收尾后，拉起下一个排队的任务。"""
    while _PENDING and len(_RUNTIME) < _max_running():
        tid, entries, payload = _PENDING.pop(0)
        _spawn(tid, entries, payload)


def start_task_multi(task_id: int, entries: list[ModelRun], budget_payload: dict[str, Any]) -> None:
    """启动一个含多个模型的任务：模型在任务内顺序执行，任务整体只占一个并发位。"""
    if not entries:
        raise TaskError("no_models", "任务至少需要一个模型")
    if task_id in _RUNTIME:
        raise TaskError("already_running", "该任务已在执行中")
    if len(_RUNTIME) >= _max_running():
        _PENDING.append((task_id, entries, budget_payload))
        _update(task_id, status=STATUS_QUEUED, stop_reason="排队中：等待前序任务完成")
        return
    _spawn(task_id, entries, budget_payload)


def start_task(task_id: int, cfg: SuiteConfig, budget: Budget) -> None:
    """单模型兼容入口：历史调用方（重测、单测）仍然只传一个配置。"""
    task = task_by_id(task_id) or {}
    model = str(task.get("model") or cfg.model)
    run_id = int(task.get("run_id") or 0)
    start_task_multi(
        task_id,
        [ModelRun(model=model, cfg=cfg, run_id=run_id)],
        {"max_requests": budget.max_requests, "max_seconds": budget.max_seconds},
    )


def _retry_write(action, attempts: int = 4):
    """Retry transient SQLite lock/readonly errors.

    WAL 模式下并发写可能瞬时失败；这类失败是可恢复的，不应把整个任务判成失败。
    """
    last: Exception | None = None
    for index in range(attempts):
        try:
            return action()
        except sqlite3.OperationalError as exc:
            text = str(exc).lower()
            if "locked" not in text and "readonly" not in text:
                raise
            last = exc
            time.sleep(0.05 * (index + 1))
    assert last is not None
    raise last


def _update(task_id: int, **fields: Any) -> None:
    if not fields:
        return
    columns = ", ".join(f"{name}=?" for name in fields)
    values = (*fields.values(), task_id)

    def action() -> None:
        with connect() as conn:
            conn.execute(f"UPDATE test_tasks SET {columns} WHERE id=?", values)

    _retry_write(action)


def _aggregate_conclusion(verdicts: list[str]) -> str:
    """任务结论 = 所有模型里最差的那个：任一不达标即不达标，没有结论即无法判定。"""
    if not verdicts:
        return VERDICT_UNDECIDED
    if VERDICT_FAIL in verdicts:
        return VERDICT_FAIL
    if VERDICT_UNDECIDED in verdicts:
        return VERDICT_UNDECIDED
    if VERDICT_PARTIAL in verdicts:
        return VERDICT_PARTIAL
    return VERDICT_PASS if all(v == VERDICT_PASS for v in verdicts) else VERDICT_UNDECIDED


# --------------------------------------------------------------------------
# 执行
# --------------------------------------------------------------------------
async def _execute(task_id: int, runtime: TaskRuntime) -> None:
    task = task_by_id(task_id)
    if task is None:  # pragma: no cover - 被并发删除
        return
    version = get_version(int(task["standard_version_id"])) if task.get("standard_version_id") else None
    if version is None:  # pragma: no cover - 创建时已校验
        _update(task_id, status=STATUS_FAILED, stop_reason="测试标准版本缺失", finished_at=now_iso())
        for entry in runtime.entries:
            update_task_run(task_id, entry.model, status=STATUS_FAILED, stop_reason="测试标准版本缺失")
        return

    results: list[tuple[str, str, str]] = []
    try:
        for index, entry in enumerate(runtime.entries):
            if runtime.cancel_reason:
                for rest in runtime.entries[index:]:
                    _cancel_run(task_id, rest, f"{runtime.cancel_reason}，未执行")
                break
            runtime.current_model = entry.model
            status, reason = await _execute_model(task_id, runtime, task, version, entry)
            results.append((entry.model, status, reason))
            if status == STATUS_CANCELLED:
                for rest in runtime.entries[index + 1:]:
                    _cancel_run(task_id, rest, f"{runtime.cancel_reason or '任务被取消'}，未执行")
                break
        # 兜底：任何没有进入结果列表的模型都明确记为取消/未执行，不留“永远排队中”。
        done = {model for model, _, _ in results}
        for entry in runtime.entries:
            if entry.model not in done:
                _cancel_run(task_id, entry, runtime.cancel_reason or "任务未执行")
        _finalize_task(task_id, runtime)
    except asyncio.CancelledError:
        for entry in runtime.entries:
            row = task_run_for(task_id, entry.model)
            if row and row.get("status") in {STATUS_QUEUED, STATUS_RUNNING}:
                _cancel_run(task_id, entry, runtime.cancel_reason or "任务被取消")
        try:
            _finalize_task(task_id, runtime, forced_status=STATUS_CANCELLED)
        finally:
            raise
    except Exception as exc:  # noqa: BLE001 - 任务失败必须落库，不吞异常
        logger.exception("测试任务执行失败 task=%s", task_id)
        message = redact_text(f"{type(exc).__name__}: {exc}", 300)
        _update(task_id, status=STATUS_FAILED, stop_reason=message[:300], error=message[:300], finished_at=now_iso())
    finally:
        for entry in runtime.entries:
            entry.cfg.wipe()
        _RUNTIME.pop(task_id, None)
        try:
            _drain_pending()
        except Exception:  # pragma: no cover - 拉起失败不应影响本任务的收尾
            logger.exception("拉起排队任务失败")


def _cancel_run(task_id: int, entry: ModelRun, reason: str) -> None:
    entry.cfg.wipe()
    update_task_run(task_id, entry.model, status=STATUS_CANCELLED,
                    stop_reason=reason[:300], finished_at=now_iso())
    with connect() as conn:
        conn.execute(
            "UPDATE suite_runs SET conclusion=? WHERE id=? AND conclusion=''",
            ("已取消", entry.run_id),
        )


async def _execute_model(
    task_id: int, runtime: TaskRuntime, task: dict[str, Any], version: Version, entry: ModelRun
) -> tuple[str, str]:
    """跑一个模型的完整流程（第 1～4 章），结果落到它自己的 run_id / task_runs 行。"""
    run_id = entry.run_id
    username = str(task.get("username") or "system")
    scope = (task.get("options") or {}).get("scope") or {"type": "task"}
    chapter_scope = int(scope["chapter"]) if scope.get("type") == "chapter" else None
    total = _progress_total(version, chapter_scope)
    budget = Budget(
        max_requests=int(runtime.budget.get("max_requests") or DEFAULT_BUDGET["max_requests"]),
        max_seconds=float(runtime.budget.get("max_seconds") or DEFAULT_BUDGET["max_seconds"]),
    )
    update_task_run(task_id, entry.model, status=STATUS_RUNNING, progress_total=total, stop_reason="")
    token = set_budget(budget)
    # run_suite() 结束时会 wipe() 掉 cfg 里的凭证，自动检查必须用独立副本，
    # 否则第 2～4 章的请求会全部变成未鉴权（401）。
    check_cfg = replace(entry.cfg)
    executed: set[str] = set()
    emit = _make_emit(task_id, run_id, version, username, executed, total)
    stop_reason = ""
    try:
        _update(task_id, status=STATUS_RUNNING, started_at=now_iso(), phase="ch1")
        # 先落"执行器未实现"的阻塞项：这些项本次无论怎么跑都不会有结论。
        _block_pending_executors(run_id, version, username, chapter_scope)

        phase1_stats: dict[str, Any] = {}
        pre_gate = ""
        if chapter_scope in (None, 1):
            pre_gate = await _run_pre_gates(task_id, check_cfg, emit, version, run_id, entry.model)

        if pre_gate:
            # 三条前置必测没过（或没结论）：按规则直接收口，不再消耗后续测试的预算。
            stop_reason = pre_gate
            scope_chapters: tuple[int, ...] = (1,) if chapter_scope == 1 else (1, 2, 3, 4)
            await _block_chapters(task_id, emit, version, scope_chapters, pre_gate, run_id=run_id)
            chapters: tuple[int, ...] = ()
        else:
            if chapter_scope is None or chapter_scope == 1:
                phase1_stats = await _run_first_chapter(task_id, entry.cfg, emit)

            if chapter_scope is None:
                gate = _gate_reason(run_id, version)
                if gate:
                    stop_reason = gate
                    await _block_chapters(task_id, emit, version, (2, 3, 4), gate, run_id=run_id)
                    chapters = ()
                else:
                    chapters = (2, 3, 4)
                warning = _gate_warning(run_id, version)
                if warning:
                    stop_reason = f"{stop_reason}；{warning}" if stop_reason else warning
            elif chapter_scope == 1:
                chapters = ()
            else:
                chapters = (chapter_scope,)

        for chapter in chapters:
            if await _chapter_disabled(task, chapter):
                await _block_chapters(
                    task_id, emit, version, (chapter,),
                    "按任务配置未启用该章节的自动测试", run_id=run_id,
                )
                continue
            await _run_chapter(task_id, check_cfg, emit, version, chapter)

        if chapter_scope is not None:
            _mark_out_of_scope(run_id, version, chapter_scope, username=username)

        if budget.exhausted_reason and not stop_reason:
            stop_reason = budget.exhausted_reason
        runtime.snapshots.append(budget.snapshot())
        _finalize_model(task_id, entry.model, run_id, version, budget, STATUS_SUCCEEDED, stop_reason, phase1_stats)
        return STATUS_SUCCEEDED, stop_reason
    except asyncio.CancelledError:
        reason = runtime.cancel_reason or "任务被取消"
        try:
            await _block_chapters(
                task_id, emit, version, (1, 2, 3, 4), f"{reason}，未执行",
                "task_interrupted", run_id=run_id,
            )
            runtime.snapshots.append(budget.snapshot())
            _finalize_model(task_id, entry.model, run_id, version, budget, STATUS_CANCELLED, reason, {})
        finally:
            raise
    except Exception as exc:  # noqa: BLE001 - 单个模型失败不能拖垮整个任务
        logger.exception("测试任务执行失败 task=%s model=%s", task_id, entry.model)
        message = redact_text(f"{type(exc).__name__}: {exc}", 300)
        try:
            runtime.snapshots.append(budget.snapshot())
            _finalize_model(task_id, entry.model, run_id, version, budget, STATUS_FAILED, message, {})
        except Exception:  # pragma: no cover - 收尾失败时至少记录错误
            update_task_run(task_id, entry.model, status=STATUS_FAILED, stop_reason=message[:300],
                            finished_at=now_iso())
        return STATUS_FAILED, message
    finally:
        reset_budget(token)
        check_cfg.wipe()


def _progress_done(run_id: int) -> int:
    def action() -> int:
        with connect() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT item_id) c FROM run_items WHERE run_id=? AND status IN (%s)"
                % ",".join("?" * len(EXECUTED_STATUSES)),
                (run_id, *EXECUTED_STATUSES),
            ).fetchone()
        return int(row["c"])

    return _retry_write(action)


def _sync_task_progress(task_id: int) -> None:
    """任务进度 = 各模型进度之和；模型内进度只看真实判定（pass/fail）。"""
    with connect() as conn:
        rows = conn.execute(
            "SELECT COALESCE(SUM(progress_done),0) d, COALESCE(SUM(progress_total),0) t "
            "FROM task_runs WHERE task_id=?",
            (task_id,),
        ).fetchone()
    _update(task_id, progress_done=int(rows["d"]), progress_total=int(rows["t"]))


def _finalize_model(
    task_id: int,
    model: str,
    run_id: int,
    version: Version,
    budget: Budget,
    status: str,
    stop_reason: str,
    phase1_stats: dict[str, Any],
) -> None:
    """一个模型收尾：写 suite_runs（历史报告复用）与 task_runs（任务内明细）。"""
    task = task_by_id(task_id)
    username = str((task or {}).get("username") or "system")
    _fill_manual_pending(run_id, version)
    entries = resolve_entries(version, load_run_items(run_id))
    verdict = conclusion(entries)

    with connect() as conn:
        counters = conn.execute(
            "SELECT result, COUNT(*) c FROM suite_cases WHERE run_id=? GROUP BY result", (run_id,)
        ).fetchall()
    counts = {str(row["result"]): int(row["c"]) for row in counters}
    passed = counts.get("PASS", 0)
    failed = counts.get("FAIL", 0)
    skipped = counts.get("SKIP", 0)

    with connect() as conn:
        conn.execute(
            "UPDATE suite_runs SET passed=?, failed=?, skipped=?, conclusion=? WHERE id=?",
            (passed, failed, skipped, verdict["verdict"], run_id),
        )
        conn.execute("UPDATE test_tasks SET phase='final' WHERE id=?", (task_id,))

    current = task_run_for(task_id, model) or {}
    total = int(current.get("progress_total") or 0)
    executed = _progress_done(run_id)
    update_task_run(
        task_id,
        model,
        status=status,
        conclusion=verdict["verdict"],
        counts=json.dumps(verdict["counts"], ensure_ascii=False),
        progress_done=min(executed, total) if total else executed,
        stop_reason=stop_reason[:300],
        finished_at=now_iso(),
    )
    _sync_task_progress(task_id)


def _finalize_task(task_id: int, runtime: TaskRuntime, forced_status: str = "") -> None:
    """所有模型跑完后汇总：结论取最差，计数相加，进度相加。"""
    rows = task_runs(task_id)
    counts: dict[str, int] = {}
    for row in rows:
        for key, value in (row.get("counts") or {}).items():
            counts[key] = counts.get(key, 0) + int(value)

    verdict = _aggregate_conclusion([str(row.get("conclusion") or "") for row in rows])
    if forced_status:
        status = forced_status
    elif any(row.get("status") == STATUS_FAILED for row in rows):
        status = STATUS_FAILED
    elif any(row.get("status") == STATUS_CANCELLED for row in rows):
        status = STATUS_CANCELLED
    else:
        status = STATUS_SUCCEEDED

    parts = []
    for row in rows:
        label = row.get("conclusion") or TASK_STATUS_LABELS.get(str(row.get("status")), "未完成")
        reason = str(row.get("stop_reason") or "").strip()
        parts.append(f"{row['model']}：{label}" + (f"（{reason}）" if reason else ""))
    stop_reason = f"{len(rows)} 个模型 · " + "；".join(parts) if parts else ""

    snapshots = runtime.snapshots or []
    total_used = sum(int(s.get("used_requests") or 0) for s in snapshots)
    total_max = sum(int(s.get("max_requests") or runtime.budget.get("max_requests") or 0) for s in snapshots) \
        or int(runtime.budget.get("max_requests") or 0)
    exhausted = "；".join(dict.fromkeys(
        str(s.get("exhausted_reason")) for s in snapshots if s.get("exhausted_reason")
    ))
    budget_summary = {
        "max_requests": total_max,
        "used_requests": total_used,
        "max_seconds": sum(float(s.get("max_seconds") or 0) for s in snapshots)
        or float(runtime.budget.get("max_seconds") or 0),
        "elapsed_seconds": round(sum(float(s.get("elapsed_seconds") or 0) for s in snapshots), 1),
        "exhausted_reason": exhausted,
        "models": len(rows),
    }
    _update(
        task_id,
        status=status,
        finished_at=now_iso(),
        counts=json.dumps(counts, ensure_ascii=False),
        conclusion=verdict,
        stop_reason=stop_reason[:300],
        budget=json.dumps(budget_summary, ensure_ascii=False),
        error=stop_reason[:300] if status == STATUS_FAILED else "",
    )
    _sync_task_progress(task_id)


def _progress_total(version: Version, chapter: int | None = None) -> int:
    total = 0
    for item in version.ordered_items():
        if not item.enabled or not item.is_auto:
            continue
        if chapter is not None and item.chapter != chapter:
            continue
        if item.chapter == 1 or item.auto_check in CHECKS:
            total += 1
    return total


def _block_pending_executors(
    run_id: int, version: Version, username: str, chapter_scope: int | None = None
) -> int:
    """把"判得了但还没写执行器"的 L2 项落 `blocked(executor_not_implemented)`。

    为什么必须显式落 blocked、不能留给"没有记录 = 未测试"：
    * `not_tested` 读起来像"运行了但上游没给证据"，会让人去查上游；
    * 真实原因是平台没实现，得有人来写代码。
    两者归因与动作完全不同，混成一个状态就会把工程债藏进被测对象的账上。

    **`chapter_scope`：按章重测时必须传本章号。** 范围外的项本次本就不该执行，
    落 `blocked(executor_not_implemented)` 会与 K3「范围外=未测试」冲突——而且
    因为 `_mark_out_of_scope` 跳过已存在的行，那个 blocked 会留下来，让「只跑第 1 章」
    的报告里出现别章的"平台未实现"。先判范围，再判执行器就绪。

    已有记录不动（可能真的跑过，例如人工登记或历史重测）。
    """
    from .executors import PENDING_REASONS, pending_spec

    with connect() as conn:
        done = {
            row["item_id"]
            for row in conn.execute("SELECT item_id FROM run_items WHERE run_id=?", (run_id,))
        }
    blocked = 0
    for item in version.ordered_items():
        if not item.enabled or item.id in done:
            continue
        if chapter_scope is not None and item.chapter != chapter_scope:
            continue
        spec = pending_spec(item)
        if spec is None:
            continue
        reason_text = PENDING_REASONS.get(str(spec["reason"]), str(spec["reason"]))
        actual = f"执行器未实现（批次 {spec['batch']}）：{reason_text}；本项说明：{spec['why']}"
        with connect() as conn:
            conn.execute(
                """INSERT INTO run_items(run_id, item_id, item_key, display_id, status, source,
                   actual, evidence, note, operator, updated_at, blocker_reason)
                   VALUES (?,?,?,?,?,?,?,'','',?,?,?)
                   ON CONFLICT(run_id, item_id) DO NOTHING""",
                (
                    run_id,
                    item.id,
                    item.key,
                    item.display_id or item.id,
                    BLOCKED,
                    "auto",
                    actual[:500],
                    username,
                    now_iso(),
                    "executor_not_implemented",
                ),
            )
        blocked += 1
    return blocked


def _make_emit(task_id: int, run_id: int, version: Version, username: str, executed: set[str], total: int):
    async def emit(kind: str, data: dict[str, Any]) -> None:
        item_id = ""
        with connect() as conn:
            if kind == "case":
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
                record_case_item(conn, run_id, data, version, username)
                item_id = str(data.get("case_id") or "")
            elif kind == "item":
                upsert_item(conn, run_id, data, username, version)
                item_id = str(data.get("item_id") or "")
        if item_id and kind in {"case", "item"}:
            executed.add(item_id)
            if total > 0:
                # 进度只统计“真的有执行结论”的项：阻塞/待确认不算已执行，
                # 否则会出现 progress_done > progress_total 的假进度。
                _sync_progress(task_id, run_id, total)

    return emit


# 进度只认"真的有判定结论"的项：pass / fail。
# 过去把 not_applicable 也算已执行（K4），于是上游一律 400 让 29 项变"不适用"时，
# 进度条照样走到 100%，页面显示"已完成"——而实际上没有任何一条被验证过。
EXECUTED_STATUSES = (PASS, FAIL)


def _sync_progress(task_id: int, run_id: int, total: int) -> None:
    """更新"某个模型"的进度，并把它汇总到任务总进度。"""
    done = min(_progress_done(run_id), total)

    def action() -> int:
        with connect() as conn:
            cursor = conn.execute(
                "UPDATE task_runs SET progress_done=?, progress_total=? WHERE run_id=?",
                (done, total, run_id),
            )
            return int(cursor.rowcount or 0)

    updated = _retry_write(action)
    if updated:
        _sync_task_progress(task_id)
    else:
        # 历史任务（迁移前创建，没有 task_runs 行）退回原来的任务级进度。
        _update(task_id, progress_done=done, progress_total=total)


def _pre_gate_items(version: Version) -> list[Any]:
    """按 PRE_GATE_IDS 的声明顺序取前置必测项（顺序即执行顺序）。"""
    order = {item_id: index for index, item_id in enumerate(PRE_GATE_IDS)}
    items = [
        item
        for item in version.ordered_items()
        if item.enabled and item.id in order and item.is_auto and item.auto_check in CHECKS
    ]
    return sorted(items, key=lambda item: order[item.id])


def _store_channel_metrics(task_id: int, model: str, results: list[Any]) -> None:
    """把前置必测量出的缓存命中率与延时分位存到 task_runs.metrics，作为渠道权重依据。"""
    metrics: dict[str, Any] = {}
    for result in results:
        try:
            payload = json.loads(result.evidence or "")
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        if result.item_id == "GATE-02":
            metrics["cache"] = {
                "hit_rate": payload.get("hit_rate"),
                "hits": payload.get("hits"),
                "calls": payload.get("calls"),
            }
        elif result.item_id == "GATE-03":
            metrics["latency"] = {
                "p5_ms": payload.get("p5_ms"),
                "p50_ms": payload.get("p50_ms"),
                "p95_ms": payload.get("p95_ms"),
                "samples": payload.get("samples"),
            }
    if not metrics:
        return
    metrics["model"] = model
    metrics["measured_at"] = now_iso()
    update_task_run(task_id, model, metrics=json.dumps(metrics, ensure_ascii=False))


def _short(text: Any, limit: int = 80) -> str:
    cleaned = str(text or "").replace("\n", " ").strip()
    return cleaned[:limit] + ("…" if len(cleaned) > limit else "")


async def _run_pre_gates(
    task_id: int, cfg: SuiteConfig, emit, version: Version, run_id: int, model: str
) -> str:
    """先跑三条前置必测。返回空串 = 全部通过，可以继续；否则返回停止原因。

    规则（2026-10-30）：这三条优先执行，任一条没通过就直接判不达标，后续测试不再执行。
    “没有判定结论”（例如请求预算耗尽）同样不再往下跑——前置项没有结论时，
    后面的 166 项跑完也判不出达标。
    """
    items = _pre_gate_items(version)
    if not items:
        return ""
    _update(task_id, phase="gate")
    results = await run_auto_checks(cfg, items, emit)
    _store_channel_metrics(task_id, model, results)

    by_id = {result.item_id: result for result in results}
    failed = [item_id for item_id in PRE_GATE_IDS if item_id in by_id and by_id[item_id].status == FAIL]
    unjudged = [
        item_id
        for item_id in PRE_GATE_IDS
        if item_id in by_id and by_id[item_id].status not in (PASS, FAIL)
    ]
    detail = lambda ids: "；".join(
        f"{item_id}：{_short(by_id[item_id].actual, 60)}" for item_id in ids
    )

    if failed:
        return f"前置必测未通过（{detail(failed)}），按规则直接判不达标，后续测试不再执行"[:300]
    if unjudged:
        return f"前置必测没有判定结论（{detail(unjudged)}），后续测试不再执行"[:300]
    return ""


async def _run_first_chapter(task_id: int, cfg: SuiteConfig, emit) -> dict[str, Any]:
    _update(task_id, phase="ch1")
    try:
        return await run_suite(cfg, emit)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - 第一章异常不应让任务整体崩溃，交给收尾判定
        return {"passed": 0, "failed": 0, "skipped": 0, "error": redact_text(str(exc), 200)}


async def _run_chapter(task_id: int, cfg: SuiteConfig, emit, version: Version, chapter: int) -> None:
    items = [
        item
        for item in version.ordered_items()
        if item.enabled and item.chapter == chapter and item.is_auto and item.auto_check in CHECKS
    ]
    if not items:
        return
    _update(task_id, phase=f"ch{chapter}")
    await run_auto_checks(cfg, items, emit)


async def _block_chapters(
    task_id: int,
    emit,
    version: Version,
    chapters: Iterable[int],
    reason: str,
    blocker_reason: str = "gate_failed",
    run_id: int | None = None,
) -> None:
    """把未执行的自动项标为阻塞。

    已有执行记录的项目一律不动——包括“取消”场景：已经跑完的用例必须保留真实结果，
    不能被收尾逻辑覆盖成“阻塞”。

    `run_id` 必须由调用方传当前模型的执行记录：多模型任务里 task.run_id 只是第一个模型，
    用它会把这些阻塞项写到别的模型账上。
    """
    if run_id is None:  # 兼容历史调用：单模型任务
        task = task_by_id(task_id)
        run_id = int((task or {}).get("run_id") or 0)
    with connect() as conn:
        done = {
            row["item_id"]
            for row in conn.execute("SELECT item_id FROM run_items WHERE run_id=?", (run_id,))
        }
    for chapter in chapters:
        for item in version.ordered_items():
            if item.chapter != chapter or not item.enabled or not item.is_auto:
                continue
            if item.id in done:
                continue
            await emit(
                "item",
                {
                    "item_id": item.id,
                    "status": BLOCKED,
                    "actual": reason,
                    "evidence": "",
                    "source": "auto",
                    "blocker_reason": blocker_reason,
                },
            )


async def _chapter_disabled(task: dict[str, Any], chapter: int) -> bool:
    options = task.get("options") or {}
    if chapter == 3 and options.get("cache_tests") is False:
        return True
    if chapter == 4 and options.get("capability_tests") is False:
        return True
    return False


def _critical_states(run_id: int, version: Version) -> list[tuple[str, str]]:
    critical = [item_id for item_id in CRITICAL_FIRST_CHAPTER if item_id in version.items]
    if not critical:
        return []
    with connect() as conn:
        rows = {
            row["item_id"]: row["status"]
            for row in conn.execute(
                "SELECT item_id, status FROM run_items WHERE run_id=? AND item_id IN (%s)"
                % ",".join("?" * len(critical)),
                (run_id, *critical),
            )
        }
    return [(item_id, rows.get(item_id, NOT_TESTED)) for item_id in critical]


def _gate_reason(run_id: int, version: Version) -> str:
    """第一章关键项门禁（K6）。

    规则：只要有任一关键项**判了不通过**，后续章节就不再消耗预算。
    过去是"任一关键项 PASS 即放行"，于是 3 红 1 绿也会照跑 130 项，
    在上游必然失败时产出一堆无意义 FAIL 并烧掉预算。

    关键项"没有判定结论"（未测试/阻塞，例如服务器没装 dig）不阻断——那属于
    平台侧缺证据，不是被测对象不合格；但它也绝不等于通过：由
    :func:`_gate_warning` 显式记录，且结论仍会落到"无法判定"。
    """
    failed = [item_id for item_id, state in _critical_states(run_id, version) if state == FAIL]
    if failed:
        return (
            f"第一章关键项未通过（{len(failed)} 项：{'、'.join(failed[:6])}），"
            "后续章节自动项标记为阻塞"
        )
    return ""


def _gate_warning(run_id: int, version: Version) -> str:
    """关键项里有"没有判定结论"的项时，显式写出来（不阻断，但不得判达标）。"""
    verdicts = _critical_states(run_id, version)
    unjudged = [item_id for item_id, state in verdicts if state not in (PASS, FAIL)]
    if not verdicts or not unjudged:
        return ""
    return (
        f"第一章关键项中有 {len(unjudged)} 项没有判定结论（{'、'.join(unjudged[:6])}"
        "），后续章节照常执行，但本次结论不得判为达标"
    )


def _mark_out_of_scope(run_id: int, version: Version, chapter: int, username: str) -> None:
    """按章重测：章外项目记为**未测试**，不是"不适用"（K3）。

    过去这里写 `not_applicable` + "该测试项未执行"，于是"只跑第 2 章"会把其余
    8 章 133 项全部从分母里摘掉，单章报告就能显示"达标"。未执行就是未测试，
    两者在结论里都不算通过，但语义与统计口径完全不同。
    """
    with connect() as conn:
        existing = {
            row["item_id"]
            for row in conn.execute("SELECT item_id FROM run_items WHERE run_id=?", (run_id,))
        }
        for item in version.ordered_items():
            if item.id in existing or not item.enabled or item.chapter == chapter:
                continue
            conn.execute(
                """INSERT INTO run_items(run_id, item_id, item_key, display_id, status, source,
                   actual, evidence, note, operator, updated_at)
                   VALUES (?,?,?,?,?,?,?,'','',?,?)
                   ON CONFLICT(run_id, item_id) DO NOTHING""",
                (
                    run_id,
                    item.id,
                    item.key,
                    item.display_id or item.id,
                    NOT_TESTED,
                    "auto",
                    f"本次为按章重测，范围仅第 {chapter} 章，该测试项未执行（未测试，不是不适用）",
                    username,
                    now_iso(),
                ),
            )


def _fill_manual_pending(run_id: int, version: Version) -> None:
    """人工项没有任何记录时标为“待确认”，而不是“未测试”。

    两者都不算通过，但“待确认”表示等人去做，“未测试”表示自动流程没能执行，
    报告里需要能区分开。
    """
    with connect() as conn:
        existing = {
            row["item_id"]
            for row in conn.execute("SELECT item_id FROM run_items WHERE run_id=?", (run_id,))
        }
        for item in version.ordered_items():
            if item.id in existing or not item.enabled or item.is_auto:
                continue
            conn.execute(
                """INSERT INTO run_items(run_id, item_id, item_key, display_id, status, source,
                   actual, evidence, note, operator, updated_at)
                   VALUES (?,?,?,?,?,?,?,'','','',?)
                   ON CONFLICT(run_id, item_id) DO NOTHING""",
                (
                    run_id,
                    item.id,
                    item.key,
                    item.display_id or item.id,
                    PENDING,
                    "manual",
                    "待人工确认：该测试项无法由平台自动判定",
                    now_iso(),
                ),
            )


# --------------------------------------------------------------------------
# 取消 / 中断 / 重算
# --------------------------------------------------------------------------
def cancel_task(task_id: int, reason: str = "用户取消") -> bool:
    runtime = _RUNTIME.get(task_id)
    if runtime is None or runtime.task is None:
        return False
    runtime.cancel_reason = reason
    runtime.task.cancel()
    return True


#: 进程重启后必须被标记为"中断"的状态集合。
#: 用**非终态**而不是 `status IN ('queued','running')` 的写法：后续批次会引入
#: 等待态（等待 TTL / 静默期），那种任务同样活在内存里、重启后无法续跑。
#: 写死成只认 running 会让新的等待态在重启后永远挂着"执行中"。
#: 若将来出现"有意暂停、重启后应当保留"的状态，需显式加进 TERMINAL_STATUSES。
TERMINAL_STATUSES: tuple[str, ...] = (
    STATUS_SUCCEEDED,
    STATUS_FAILED,
    STATUS_CANCELLED,
    STATUS_INTERRUPTED,
)

#: 中断原因的机器可读标记（写进 stop_reason 前缀，便于运维 grep）：
#: test_tasks 表没有 block_reason 列，且本批次不允许加列。
INTERRUPT_REASON_CODE = "task_interrupted"


def mark_interrupted_tasks() -> int:
    """进程重启后，内存里的凭证已消失，运行中的任务不能假装还在跑。

    任何**非终态**任务都会被标记为中断——包括将来可能出现的等待态。
    """
    with connect() as conn:
        cursor = conn.execute(
            """UPDATE test_tasks
               SET status=?, stop_reason=?, finished_at=?
               WHERE status NOT IN (%s)"""
            % ",".join("?" * len(TERMINAL_STATUSES)),
            (
                STATUS_INTERRUPTED,
                f"{INTERRUPT_REASON_CODE}：服务重启，任务中断；凭证已随进程释放，请重新执行",
                now_iso(),
                *TERMINAL_STATUSES,
            ),
        )
        return int(cursor.rowcount or 0)


def recompute(task_id: int, model: str = "") -> dict[str, Any]:
    """Re-derive counts and verdict after a manual confirmation or retest.

    ``model`` 指定只重算某个模型；不指定则重算全部模型并汇总任务结论。
    历史任务（没有 task_runs 明细）仍按原来的单 run 逻辑处理。
    """
    task = task_by_id(task_id)
    if task is None:
        raise TaskError("not_found", "任务不存在")
    if not task.get("standard_version_id"):
        raise TaskError("standard_missing", "该任务未绑定测试标准版本")
    version = get_version(int(task["standard_version_id"]))
    if version is None:
        raise TaskError("standard_missing", "测试标准版本不存在")

    rows = task_runs(task_id)
    if not rows:
        run_id = int(task.get("run_id") or 0)
        entries = resolve_entries(version, load_run_items(run_id))
        verdict = conclusion(entries)
        _update(task_id, counts=json.dumps(verdict["counts"], ensure_ascii=False),
                conclusion=verdict["verdict"])
        with connect() as conn:
            conn.execute("UPDATE suite_runs SET conclusion=? WHERE id=?", (verdict["verdict"], run_id))
        return verdict

    targets = [model] if model else [str(row["model"]) for row in rows]
    verdicts: list[dict[str, Any]] = []
    for name in targets:
        row = task_run_for(task_id, name)
        if row is None:
            continue
        run_id = int(row["run_id"])
        item_entries = resolve_entries(version, load_run_items(run_id))
        verdict = conclusion(item_entries)
        update_task_run(
            task_id, name,
            conclusion=verdict["verdict"],
            counts=json.dumps(verdict["counts"], ensure_ascii=False),
        )
        with connect() as conn:
            conn.execute("UPDATE suite_runs SET conclusion=? WHERE id=?", (verdict["verdict"], run_id))
        verdicts.append(verdict)

    rows = task_runs(task_id)
    totals: dict[str, int] = {}
    for row in rows:
        for key, value in (row.get("counts") or {}).items():
            totals[key] = totals.get(key, 0) + int(value)
    aggregate = {
        "verdict": _aggregate_conclusion([str(row.get("conclusion") or "") for row in rows]),
        "counts": totals,
        "models": [
            {"model": row["model"], "conclusion": row.get("conclusion") or "",
             "counts": row.get("counts") or {}}
            for row in rows
        ],
    }
    _update(task_id, counts=json.dumps(totals, ensure_ascii=False), conclusion=aggregate["verdict"])
    return aggregate


# --------------------------------------------------------------------------
# 单用例重测
# --------------------------------------------------------------------------
async def run_single_item(
    task_id: int, item_id: str, secret: str, forward_secret: str = "", model: str = ""
) -> dict[str, Any]:
    task = task_by_id(task_id)
    if task is None:
        raise TaskError("not_found", "任务不存在")
    if is_running(task_id):
        raise TaskError("already_running", "任务正在执行，请等待完成后再重测单项")
    version = get_version(int(task["standard_version_id"])) if task.get("standard_version_id") else None
    if version is None:
        raise TaskError("standard_missing", "该任务未绑定测试标准版本")
    item = version.items.get(item_id)
    if item is None:
        raise TaskError("item_not_found", "测试项不存在")
    if item.chapter == 1:
        raise TaskError("suite_required", "第一章用例依赖整批执行状态，请使用“按章节/整个任务重测”")
    check = CHECKS.get(item.auto_check or "")
    if check is None:
        raise TaskError("not_automatic", "该测试项没有自动检查实现，请使用人工确认")

    row = task_run_for(task_id, model)
    selected_model = str(row["model"]) if row else str(task.get("model") or "")
    cfg = build_suite_config(task, secret, forward_secret)
    if selected_model:
        # 用当前所选模型重建配置：一个任务里有多个模型，不能拿首个模型的配置去测别的模型。
        cfg.model = selected_model
        cfg.forward_model = selected_model
    budget = Budget(max_requests=3, max_seconds=120)
    token = set_budget(budget)
    run_id = int(row["run_id"]) if row else int(task["run_id"])
    try:
        with connect() as conn:
            previous = conn.execute(
                "SELECT status, actual FROM run_items WHERE run_id=? AND item_id=?", (run_id, item_id)
            ).fetchone()
        try:
            result = await check(cfg)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise TaskError("check_failed", f"重测执行异常：{redact_text(str(exc), 160)}") from exc
        with connect() as conn:
            upsert_item(
                conn,
                run_id,
                {
                    "item_id": item_id,
                    "status": result.status,
                    "actual": result.actual,
                    "evidence": result.evidence,
                    "source": "auto",
                },
                str(task.get("username") or ""),
                version,
            )
            conn.execute(
                """INSERT INTO retest_log(task_id, item_id, scope, previous_status, previous_actual,
                   new_status, new_actual, operator, created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    task_id,
                    item_id,
                    "item",
                    str(previous["status"]) if previous else "",
                    str(previous["actual"]) if previous else "",
                    result.status,
                    result.actual[:500],
                    str(task.get("username") or ""),
                    now_iso(),
                ),
            )
    finally:
        reset_budget(token)
        cfg.wipe()

    verdict = recompute(task_id, selected_model)
    return {
        "item_id": item_id,
        "model": selected_model,
        "status": result.status,
        "actual": result.actual,
        "evidence": result.evidence,
        "conclusion": verdict,
        "budget": budget.snapshot(),
    }


def record_retest(task_id: int, item_id: str, scope: str, previous: Any, new_status: str, new_actual: str, operator: str) -> None:
    with connect() as conn:
        conn.execute(
            """INSERT INTO retest_log(task_id, item_id, scope, previous_status, previous_actual,
               new_status, new_actual, operator, created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                task_id,
                item_id,
                scope,
                str(previous["status"]) if previous else "",
                str(previous["actual"]) if previous else "",
                new_status,
                (new_actual or "")[:500],
                operator,
                now_iso(),
            ),
        )
