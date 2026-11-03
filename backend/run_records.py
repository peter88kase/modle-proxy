"""Writers for per-run execution records.

``suite_cases`` 保存第一章每条用例的原始执行结果，``run_items`` 保存“标准项 → 判定”
的统一视图（第一～四章共用）。这两个写入口被旧的 SSE 套件接口与新的后台任务引擎
共用，避免两套实现出现判定口径差异。
"""

from __future__ import annotations

from typing import Any

from .db import now_iso
from .security import redact_text
from .standards import (
    BLOCKED,
    FAIL,
    NOT_TESTED,
    PASS,
    PENDING,
    normalise_auto_na,
    normalise_blocker,
)

# 同一 case_id 在双链路下会出现两次，合并时取"最差"状态：
# 任一条链路不通过即为不通过，其次待确认、未测试，全部通过才是通过。
CASE_STATUS_RANK = {PASS: 0, NOT_TESTED: 1, PENDING: 2, FAIL: 3}


def _keys_for(standard: Any, display_id: str) -> tuple[str, str]:
    """返回 (item_key, display_id) 两列的值。

    `item_id` 列始终存原文编号（报告与人工复核按它对原文，也是回滚锚点）；
    `item_key` 存版本内键（`ch{N}:{id}`）。取不到版本时退回 display_id，
    保证"漏传"表现为 item_key = 原文编号，而不是空串——空串会被
    `ux_run_items_key` 在同一批次第二次写入时直接拒掉。
    """
    item = standard.items.get(display_id) if standard is not None else None
    if item is None:
        return display_id, display_id
    return (item.key or display_id), (item.display_id or display_id)


def case_status(result: str, execution: str) -> str:
    """把套件用例结果（PASS / FAIL / SKIP）映射为单项判定状态。

    SKIP 表示“本次没有执行证据”：人工项转为“待确认”（需授权人员核实），
    自动项转为“未测试”（条件不具备，绝不默认通过）。
    """
    if result == "PASS":
        return PASS
    if result == "FAIL":
        return FAIL
    return PENDING if execution == "manual" else NOT_TESTED


def record_case_item(
    conn: Any, run_id: int, data: dict[str, Any], standard: Any, username: str
) -> None:
    """把第一章用例结果写入 run_items，使报告与第 2～4 章共用同一判定数据源。"""
    case_id = str(data.get("case_id") or "")
    item = standard.items.get(case_id) if standard is not None else None
    if item is None:
        # 旧标准版本（仅第 2～4 章）不包含第一章项，不写入，避免污染历史判定。
        return
    status = case_status(str(data.get("result") or ""), item.execution)
    title = str(data.get("title") or "").strip()
    evidence = redact_text(str(data.get("evidence") or ""), 260)
    http_status = data.get("http_status")
    latency = data.get("latency_ms")
    actual = title
    if http_status:
        actual += f"；HTTP {http_status}"
    if latency is not None:
        actual += f"；{latency}ms"
    if evidence:
        actual += f"；{evidence}"
    actual = actual[:500]

    row = conn.execute(
        "SELECT status, actual, evidence FROM run_items WHERE run_id=? AND item_id=?",
        (run_id, case_id),
    ).fetchone()
    if row is not None:
        if CASE_STATUS_RANK.get(status, 1) < CASE_STATUS_RANK.get(str(row["status"]), 1):
            status = str(row["status"])
        previous = str(row["actual"] or "")
        if previous and actual and previous != actual:
            actual = f"{previous}；{actual}"[:500]
        previous_evidence = str(row["evidence"] or "")
        if previous_evidence and evidence:
            evidence = f"{previous_evidence}；{evidence}"[:500]

    raw_status = str(data.get("status") or "")
    status, blocker_reason = normalise_blocker(status, str(data.get("blocker_reason") or ""))
    note = str(data.get("note") or "")
    if raw_status == BLOCKED and status != BLOCKED:
        note = (note + "；" if note else "") + "记录为阻塞但缺少 blocker_reason 枚举值，按未测试处理（平台缺陷）"
    # 自动 NA 在写入侧就归一成 pending：库里存什么，读表的人就看到什么，
    # 不能指望每个消费者都记得"要读 entries 而不是 run_items"。
    status, note = normalise_auto_na(status, "auto", note)
    item_key, display_id = _keys_for(standard, case_id)
    conn.execute(
        """INSERT INTO run_items(run_id, item_id, item_key, display_id, status, source, actual,
           evidence, note, operator, updated_at, blocker_reason)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(run_id, item_id) DO UPDATE SET
             status=excluded.status, actual=excluded.actual, evidence=excluded.evidence,
             source=excluded.source, updated_at=excluded.updated_at,
             blocker_reason=excluded.blocker_reason,
             item_key=excluded.item_key, display_id=excluded.display_id""",
        (
            run_id, case_id, item_key, display_id, status, "auto", actual,
            evidence, note, username, now_iso(), blocker_reason,
        ),
    )


def upsert_item(
    conn: Any, run_id: int, data: dict[str, Any], username: str, standard: Any = None
) -> None:
    """写入一项自动检查结果（第 2～4 章，或单用例重测）。

    `blocked` 必须带枚举内的 `blocker_reason`，否则按未测试落库（fail-closed）：
    宁可显示"未测试"，也不要留一条说不出原因的"阻塞"。
    """
    raw_status = str(data.get("status", "not_tested"))
    source = str(data.get("source", "auto"))
    status, blocker_reason = normalise_blocker(raw_status, str(data.get("blocker_reason") or ""))
    # 保留调用方给的 note（例如 `na_basis=...` 受控依据），否则依据在写库时就被丢了
    note = str(data.get("note") or "")
    if raw_status == BLOCKED and status != BLOCKED:
        note = (note + "；" if note else "") + "记录为阻塞但缺少 blocker_reason 枚举值，按未测试处理（平台缺陷）"
    status, note = normalise_auto_na(status, source, note)
    display_id = str(data.get("item_id", ""))
    item_key, resolved_display = _keys_for(standard, display_id)
    conn.execute(
        """INSERT INTO run_items(run_id, item_id, item_key, display_id, status, source, actual,
           evidence, note, operator, updated_at, blocker_reason)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(run_id, item_id) DO UPDATE SET
             status=excluded.status, actual=excluded.actual, evidence=excluded.evidence,
             source=excluded.source, updated_at=excluded.updated_at,
             blocker_reason=excluded.blocker_reason,
             item_key=excluded.item_key, display_id=excluded.display_id""",
        (
            run_id,
            display_id,
            item_key,
            resolved_display,
            status,
            data.get("source", "auto"),
            data.get("actual", ""),
            data.get("evidence", ""),
            note,
            username,
            now_iso(),
            blocker_reason,
        ),
    )
