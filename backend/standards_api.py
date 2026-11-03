"""第 1～4 章测试标准配置、逐项判定与 PDF 报告导出。"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from . import tasks as task_store
from .db import audit, connect, now_iso
from .deps import client_ip_of, require_admin, require_csrf, require_operator
from .executors import executor_stats
from .report_pdf import SCOPE_NAMES, build_batch_report, build_report, font_source, suggested_filename
from .security import SessionContext
from .standards import (
    BLOCKED,
    FAIL,
    critical_without_verdict,
    NOT_APPLICABLE,
    NOT_TESTED,
    PASS,
    PENDING,
    STATUS_LABELS,
    UNDEFINED,
    Version,
    conclusion,
    create_version,
    definition,
    get_version,
    list_versions,
    load_run_items,
    report_number,
    resolve_entries,
    sync_from_definition,
)

router = APIRouter(prefix="/api", tags=["standards"])

MANUAL_STATUSES = {PASS, FAIL, NOT_TESTED, PENDING, UNDEFINED, NOT_APPLICABLE}
NOTE_REQUIRED = {FAIL, NOT_APPLICABLE}


class ItemEdit(BaseModel):
    item_id: str = Field(min_length=1, max_length=32)
    enabled: bool | None = None
    requirement: str | None = Field(default=None, max_length=16)
    params: dict[str, str] | None = None


class VersionPayload(BaseModel):
    parent_id: int = Field(ge=1)
    note: str = Field(default="", max_length=200)
    items: list[ItemEdit] = Field(default_factory=list)


class ItemResultPayload(BaseModel):
    status: str = Field(min_length=1, max_length=16)
    note: str = Field(default="", max_length=500)
    actual: str = Field(default="", max_length=500)


def _run_or_404(run_id: int) -> dict[str, Any]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM suite_runs WHERE id=?", (run_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "测试记录不存在"})
    return dict(row)


def _assert_can_view(session: SessionContext, run: dict[str, Any]) -> None:
    if session.role == "admin":
        return
    if run.get("user_id") != session.user_id:
        raise HTTPException(
            status_code=403,
            detail={"code": "forbidden", "message": "无权访问他人的测试记录"},
        )


def _version_for_run(run: dict[str, Any]) -> Version:
    version_id = run.get("standard_version_id")
    if not version_id:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "no_standard",
                "message": "该测试批次未绑定测试标准版本，无法生成判定与报告。请在接口测试页勾选测试标准后重新执行。",
            },
        )
    version = get_version(int(version_id))
    if version is None:
        raise HTTPException(status_code=409, detail={"code": "standard_missing", "message": "测试标准版本已不存在"})
    stored = (run.get("standard_checksum") or "").strip()
    if stored and stored != version.checksum:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "standard_checksum_mismatch",
                "message": "测试标准版本校验失败：记录绑定的标准快照与当前版本不一致，已拒绝导出。",
            },
        )
    return version


def _run_owner(run: dict[str, Any]) -> str:
    """执行人：取自创建该批次的账号，账号已删除时降级为记录中的用户 ID。"""
    user_id = run.get("user_id")
    if not user_id:
        return "未记录"
    with connect() as conn:
        row = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    return row["username"] if row else f"用户 #{user_id}"


def _suite_cases(run_id: int) -> list[dict[str, Any]]:
    """第一章用例的真实执行行（可能包含直连与转发两条链路）。"""
    with connect() as conn:
        rows = conn.execute(
            """SELECT case_id, title, result, evidence, http_status, latency_ms
               FROM suite_cases WHERE run_id=? ORDER BY id""",
            (run_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def _suite_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """按小节汇总第一章执行结果，用于报告第三节。"""
    groups: dict[str, dict[str, Any]] = {}
    for row in cases:
        case_id = str(row["case_id"])
        prefix = case_id.split("-", 1)[0]
        group = groups.setdefault(
            prefix,
            {"prefix": prefix, "total": 0, "pass": 0, "fail": 0, "skip": 0, "cases": []},
        )
        group["total"] += 1
        result = str(row["result"])
        if result == "PASS":
            group["pass"] += 1
        elif result == "FAIL":
            group["fail"] += 1
        else:
            group["skip"] += 1
        group["cases"].append(row)
    order = ["NET", "REQ", "STREAM", "AUTH", "MODEL", "TIME"]
    ordered = sorted(groups.values(), key=lambda g: order.index(g["prefix"]) if g["prefix"] in order else 99)
    total = len(cases)
    passed = sum(1 for row in cases if row["result"] == "PASS")
    failed = sum(1 for row in cases if row["result"] == "FAIL")
    return {
        "total": total,
        "pass": passed,
        "fail": failed,
        "skip": total - passed - failed,
        "groups": ordered,
    }


def _chapter_summary(entries: list[dict[str, Any]], titles: dict[int, str]) -> list[dict[str, Any]]:
    """分章统计，避免只看总数时忽略某一章的集中失败。"""
    grouped: dict[int, list[dict[str, Any]]] = {}
    for entry in entries:
        grouped.setdefault(int(entry["chapter"]), []).append(entry)
    summary = []
    for chapter in sorted(grouped):
        items = grouped[chapter]
        applicable = [e for e in items if not e["excluded"]]
        counts: dict[str, int] = {}
        for entry in applicable:
            counts[entry["status"]] = counts.get(entry["status"], 0) + 1
        summary.append(
            {
                "no": chapter,
                "title": titles.get(chapter, f"第{chapter}章"),
                "total": len(items),
                "applicable": len(applicable),
                "excluded": len(items) - len(applicable),
                "counts": counts,
            }
        )
    return summary


def build_context(run_id: int) -> dict[str, Any]:
    """Assemble everything the PDF needs, recalculating the verdict from stored facts."""
    run = _run_or_404(run_id)
    version = _version_for_run(run)
    run_items = load_run_items(run_id)
    entries = resolve_entries(version, run_items)
    verdict = conclusion(entries)

    link_label = " + ".join(
        {"direct": "上游直连", "forward": "转发链路"}.get(part, part)
        for part in str(run.get("link") or "").split("+")
        if part
    )
    auto_count = sum(1 for e in entries if e.item.is_auto)
    executed_auto = sum(
        1 for e in entries if e.item.is_auto and e.status in {PASS, FAIL, NOT_APPLICABLE}
    )
    manual_count = len(entries) - auto_count
    operator = _run_owner(run)

    chapters = sorted({item.chapter for item in version.items.values()})
    # 章节标题**只能**来自版本快照。过去这里读 definition()，于是改一次 config，
    # 所有历史批次重出的报告标题都会跟着变——报告就不再是"当时那份"了。
    titles = version.chapter_titles()
    chapters_backfilled = version.chapters_backfilled()
    executors = executor_stats(list(version.items.values()))
    has_first_chapter = 1 in chapters
    cases = _suite_cases(run_id)
    suite = _suite_summary(cases)

    source_label = (
        f"{version.source_document} 第 {'、'.join(str(no) for no in chapters)} 章，共 {version.item_count} 项"
    )
    task = task_store.task_by_run(run_id)
    evidence = task_store.evidence_for(int(task["id"])) if task else []
    retests = task_store.retest_history(int(task["id"])) if task else []

    adapter_label = {
        "openai": "OpenAI 兼容接口",
        "anthropic": "Anthropic 接口",
        "gemini": "Gemini 接口",
    }.get(str(run["adapter"]), str(run["adapter"]))
    def _stamp(value: str) -> str:
        """把 ISO 时间压成对外可读的「2026-10-30 10:13」。"""
        text = str(value or "").strip()
        if not text:
            return ""
        head = text.replace("T", " ")[:16]
        return head

    started = _stamp(run["created_at"])
    finished = ""
    if task:
        started = _stamp(task.get("started_at")) or started
        finished = _stamp(task.get("finished_at"))
    if finished:
        # 同一天的任务只写一次日期：2026-10-30 10:13 至 10:15（UTC）
        head = finished.split(" ")[0]
        tail = finished.split(" ", 1)[1] if " " in finished else finished
        when = f"{started} 至 {tail if head == started.split(' ')[0] else finished}（UTC）"
    else:
        when = f"{started}（UTC）"

    meta_rows = [("被测模型", run["model"]), ("接口协议", adapter_label)]
    provider_name = str(run.get("provider_name") or "")
    # 供应商名等于模型名（或就是 custom 占位）时没有信息量，不重复占一行
    if provider_name not in {"", "custom", str(run["model"])}:
        meta_rows.append(("服务商 / 渠道", provider_name))
    meta_rows.extend(
        [
            ("接口地址", str(run.get("endpoint_host") or "未记录")),
            ("测试时间", when),
            ("测试范围", "、".join(SCOPE_NAMES.get(no, f"第 {no} 部分") for no in chapters)),
            ("测试依据", f"《新供应商引入测试标准》第 1～4 章 · 版本 {version.version}"),
        ]
    )

    # 对外结论说明：只解释"依据什么、怎么判、覆盖到哪"，不写内部实现细节
    notes = [
        "1. 本报告依据《新供应商引入测试标准》第 1～4 章逐项检查：平台对被测接口发起真实请求，"
        "并按各项的通过标准判定结果。",
        "2. 三项前置必测（单次调用连通性、缓存命中率、响应延时分位）优先执行；任一项未通过，"
        "整体即判定为不达标，其余检查不再执行。",
        "3. 判定口径：全部适用项通过为「达标」；存在未通过项为「不达标」；存在未执行或待确认项、"
        "且没有未通过项时为「无法判定」或「部分完成，待人工确认」。",
        "4. 本结论仅覆盖本次被测的模型、协议与链路组合，不自动适用于同一供应商的其他模型或其他协议。",
        "5. 报告中不含 API Key、Authorization 请求头等凭证信息；请求与响应文本已脱敏并截断。",
    ]
    if not has_first_chapter:
        notes.insert(
            3,
            "4. 本次测试范围不含「连通性与鉴权」部分，该部分记录仅供参考，不参与整体结论。",
        )
    if chapters_backfilled:
        notes.append("6. 该批次的标准章节信息为后补记录，个别标题可能与当期文档用词略有差异。")

    incomplete_reason = ""
    if any(entry.status in {BLOCKED, NOT_TESTED} for entry in entries):
        stop_reason = str((task or {}).get("stop_reason") or "")
        if "前置必测" in stop_reason:
            incomplete_reason = "前置必测未通过，后续检查按规则停止"
        elif "预算" in stop_reason:
            incomplete_reason = "本次执行的请求预算已用尽"
        elif stop_reason:
            incomplete_reason = "本次执行提前结束"
        else:
            incomplete_reason = "前置条件不足或该能力暂不支持自动判定"

    return {
        "run": run,
        "version": version,
        # 多模型合并报告要按模型归组，这里把模型与标准标签一并给出去，
        # 免得报告层再去 meta_rows 里按中文标签捞。
        "model": str(run["model"]),
        "standard_label": f"《新供应商引入测试标准》第 1～4 章 · 版本 {version.version}",
        "entries": [entry.as_dict() for entry in entries],
        "conclusion": verdict,
        "report_no": report_number(run_id, run["created_at"]),
        "generated_at": now_iso(),
        "meta_rows": meta_rows,
        "notes": notes,
        "incomplete_reason": incomplete_reason,
        "chapter_summary": _chapter_summary([entry.as_dict() for entry in entries], titles),
        # 关键项缺结论要在报告第二节点名（不能只写进接口的 stop_reason）
        "critical_no_verdict": critical_without_verdict(entries),
        "suite_summary": suite,
        "suite_cases": cases,
        "has_first_chapter": has_first_chapter,
        "chapters_backfilled": chapters_backfilled,
        "executor_stats": executors,
        "task": task,
        "evidence": evidence,
        "retests": retests,
    }


@router.get("/standards")
def standards_overview(session: SessionContext = Depends(require_operator)) -> dict:
    spec = definition()
    return {
        "standard_id": spec["standard_id"],
        "title": spec["title"],
        "source_document": spec["source_document"],
        "chapters": spec["chapters"],
        "item_count": len(spec["items"]),
        "versions": list_versions(),
        "pdf_font": font_source(),
        "statuses": STATUS_LABELS,
    }


@router.get("/standards/versions/{version_id}")
def standards_version(version_id: int, session: SessionContext = Depends(require_operator)) -> dict:
    version = get_version(version_id)
    if version is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "标准版本不存在"})
    items = [item.as_payload() for item in version.ordered_items()]
    return {
        "id": version.id,
        "standard_id": version.standard_id,
        "version": version.version,
        "checksum": version.checksum,
        "item_count": version.item_count,
        "created_at": version.created_at,
        "created_by": version.created_by,
        "note": version.note,
        "parent_id": version.parent_id,
        "items": items,
    }


@router.post("/standards/versions")
def create_standard_version(
    payload: VersionPayload, request: Request, session: SessionContext = Depends(require_admin)
) -> dict:
    require_csrf(request, session)
    from .standards import StandardsError

    try:
        version = create_version(
            payload.parent_id,
            [edit.model_dump(exclude_none=True) for edit in payload.items],
            session.username,
            payload.note,
        )
    except StandardsError as exc:
        raise HTTPException(status_code=400, detail={"code": "invalid_standard", "message": str(exc)})
    audit(
        session.user_id,
        session.username,
        "standard_version_created",
        client_ip_of(request),
        f"version={version.id} checksum={version.checksum} edits={len(payload.items)}",
    )
    return {
        "ok": True,
        "id": version.id,
        "version": version.version,
        "checksum": version.checksum,
        "item_count": version.item_count,
    }


@router.post("/standards/sync")
def sync_standard_version(request: Request, session: SessionContext = Depends(require_admin)) -> dict:
    """把包内标准定义同步成新版本（仅管理员）。

    升级后若最新版本恰好是人工保存的，启动时的自动同步会跳过；这个按钮就是那种情况的手动补口。
    """
    require_csrf(request, session)
    new_id = sync_from_definition(session.username)
    if new_id is None:
        return {"ok": True, "created": False, "message": "库中最新版本已与包内定义一致，无需同步"}
    version = get_version(new_id)
    audit(
        session.user_id,
        session.username,
        "standard_version_synced",
        client_ip_of(request),
        f"version={new_id} item_count={version.item_count if version else 0}",
    )
    return {
        "ok": True,
        "created": True,
        "id": new_id,
        "version": version.version if version else "",
        "item_count": version.item_count if version else 0,
    }


@router.get("/runs/{run_id}/report")
def report_preview(run_id: int, session: SessionContext = Depends(require_operator)) -> dict:
    run = _run_or_404(run_id)
    _assert_can_view(session, run)
    context = build_context(run_id)
    return {
        "run_id": run_id,
        "report_no": context["report_no"],
        "standard": {
            "id": context["version"].id,
            "version": context["version"].version,
            "checksum": context["version"].checksum,
            "item_count": context["version"].item_count,
        },
        "conclusion": context["conclusion"],
        "entries": context["entries"],
        "generated_at": context["generated_at"],
    }


@router.post("/runs/{run_id}/items/{item_id}")
def update_item_result(
    run_id: int,
    item_id: str,
    payload: ItemResultPayload,
    request: Request,
    session: SessionContext = Depends(require_operator),
) -> dict:
    require_csrf(request, session)
    run = _run_or_404(run_id)
    _assert_can_view(session, run)
    version = _version_for_run(run)
    item = version.items.get(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "item_not_found", "message": "测试项不存在"})
    if payload.status not in MANUAL_STATUSES:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_status", "message": f"不支持的状态：{payload.status}"},
        )
    if payload.status in NOTE_REQUIRED and not payload.note.strip():
        raise HTTPException(
            status_code=400,
            detail={"code": "note_required", "message": "标记为不通过或不适用时必须填写说明"},
        )

    with connect() as conn:
        conn.execute(
            """INSERT INTO run_items(run_id, item_id, item_key, display_id, status, source,
               actual, evidence, note, operator, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(run_id, item_id) DO UPDATE SET
                 status=excluded.status, actual=excluded.actual, note=excluded.note,
                 operator=excluded.operator, updated_at=excluded.updated_at, source='manual',
                 item_key=excluded.item_key, display_id=excluded.display_id""",
            (
                run_id,
                item_id,
                item.key,
                item.display_id or item_id,
                payload.status,
                "manual",
                payload.actual.strip()[:500],
                "",
                payload.note.strip()[:500],
                session.username,
                now_iso(),
            ),
        )

    entries = resolve_entries(version, load_run_items(run_id))
    verdict = conclusion(entries)
    with connect() as conn:
        conn.execute("UPDATE suite_runs SET conclusion=? WHERE id=?", (verdict["verdict"], run_id))
    audit(
        session.user_id,
        session.username,
        "standard_item_updated",
        client_ip_of(request),
        f"run={run_id} item={item_id} status={payload.status}",
    )
    return {"ok": True, "item_id": item_id, "conclusion": verdict}


def _export_batch(run: dict[str, Any]) -> tuple[bytes, dict[str, Any], str, list[str]]:
    """组装多模型合并报告。

    两种数据形态都支持：
    * 新任务：一个 task 下挂多个 task_runs（每个模型一条 suite_runs），直接全取；
    * 历史批次：多个 task 用 batch_id 归组，批次内**每个模型取最新一条任务**。
    """
    task = task_store.task_by_run(int(run["id"]))
    task_id = int(task["id"]) if task else 0
    rows = task_store.task_runs(task_id) if task else []
    if len(rows) >= 2:
        contexts = [build_context(int(row["run_id"])) for row in rows]
        batch_id = f"TASK-{task_id}"
        batch = {
            "batch_id": batch_id,
            "created_at": str((task or {}).get("created_at") or ""),
            # 对外只给报告编号，不暴露内部批次号（BATCH-xxx / TASK-xxx）
            "report_no": contexts[0]["report_no"],
        }
        try:
            content = build_batch_report(contexts, batch)
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=500,
                detail={"code": "report_failed", "message": f"合并报告生成失败：{type(exc).__name__}"},
            )
        filename = suggested_filename(f"task-{task_id}", batch["created_at"]).replace(
            "测试结果报告", "多模型测试结果报告"
        )
        return content, contexts[0], filename, [batch_id]

    batch_id = str((task or {}).get("batch_id") or "")
    if not batch_id:
        raise HTTPException(
            status_code=409,
            detail={"code": "batch_missing", "message": "该任务只有单个模型，只能导出单任务报告"},
        )
    tasks = task_store.latest_per_model(task_store.batch_tasks(batch_id))
    with_run = [t for t in tasks if t.get("run_id")]
    if len(with_run) < 2:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "batch_too_small",
                "message": f"该批次只有 {len(with_run)} 个模型有执行记录，合并报告至少需要 2 个："
                "请确认是否用了批量模型提交",
            },
        )
    contexts = [build_context(int(t["run_id"])) for t in with_run]
    created_at = str((task or {}).get("created_at") or "")
    batch = {
        "batch_id": batch_id,
        "created_at": created_at,
        "report_no": contexts[0]["report_no"],
    }
    try:
        content = build_batch_report(contexts, batch)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - 生成失败必须显式返回，不静默
        raise HTTPException(
            status_code=500,
            detail={"code": "report_failed", "message": f"合并报告生成失败：{type(exc).__name__}"},
        )
    filename = suggested_filename(f"batch-{batch_id}", created_at).replace(
        "测试结果报告", "多模型测试结果报告"
    )
    # 审计与返回都用第一个模型上下文做代表；批量结论单独在报告里给出
    return content, contexts[0], filename, [batch_id]


@router.get("/runs/{run_id}/report.pdf")
def export_report(
    run_id: int,
    request: Request,
    scope: Literal["task", "batch"] = "task",
    session: SessionContext = Depends(require_operator),
):
    """导出 PDF。``scope=batch`` 把同一次提交里的**所有模型**合并成一份。

    为什么按 run_id 而不是 batch_id 取：前端手里本来就有 run_id，
    再让它在 URL 里拼批次号会把"这个批次属于谁"的鉴权判断分散到两处。
    """
    run = _run_or_404(run_id)
    _assert_can_view(session, run)
    batch_ids: list[str] = []
    if scope == "batch":
        content, context, filename, batch_ids = _export_batch(run)
    else:
        context = build_context(run_id)
        try:
            content = build_report(context)
        except Exception as exc:  # noqa: BLE001 - 生成失败必须显式返回，不静默
            raise HTTPException(
                status_code=500,
                detail={"code": "report_failed", "message": f"报告生成失败：{type(exc).__name__}"},
            )
        filename = suggested_filename(context["report_no"], run["created_at"])
    audit(
        session.user_id,
        session.username,
        "report_exported",
        client_ip_of(request),
        f"run={run_id} scope={scope} report={context['report_no']} "
        f"verdict={context['conclusion']['verdict']}"
        + (f" batch={batch_ids[0]}" if batch_ids else ""),
    )
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=\"report-{run_id}.pdf\"; filename*=UTF-8''{_quote(filename)}",
            "Cache-Control": "no-store",
        },
    )


def _quote(name: str) -> str:
    from urllib.parse import quote

    return quote(name)
