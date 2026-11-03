"""第 1～4 章测试标准：定义加载、版本管理、判定计算。

设计要点
--------
* 标准定义来自两份 JSON：``config/standards_ch1.json``（第一章「连通性与鉴权」33 项，
  与 ``backend/suite.py`` 的 case_id 一一对应）与 ``config/standards_ch234.json``
  （第 2～4 章 133 项，由 Word 内嵌表格抽取）。运行时合并为一份定义。
* 版本只增不改：任何配置修改都会复制出新版本，历史测试记录与其报告始终绑定当时
  的 ``version_id``，因此不会出现“改标准后历史报告被静默覆盖”。
* 判定完全由后端计算：状态来源只有两种——自动检查写入的真实执行结果，或授权用户
  的人工确认；没有记录的一律视为“未测试”，绝不默认通过。
"""

from __future__ import annotations

import hashlib
import re
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .config import BASE_DIR
from .db import connect, now_iso

DEFINITION_PATHS = (
    BASE_DIR / "config" / "standards_ch1.json",
    BASE_DIR / "config" / "standards_ch234.json",
)

# 合并后的标准元信息。版本号在定义内容变化时递增，用于 seed 与同步时的显示。
# 注意：sync_definition() 读的是这里的 version，不是各 standards_*.json 里的 version
# （后者是死字段，改了不生效也不报错）。B0.5b 要让前者从 JSON 单向派生。
MERGED_META = {
    "standard_id": "CH1-4",
    "version": "2026.10.30-1",
    "title": "第 1～4 章：连通性与鉴权 / 接口兼容性 / 缓存正确性 / 模型与能力真实性",
    "source_chapters": [1, 2, 3, 4],
}

# --- 单项状态 ---------------------------------------------------------------
PASS = "pass"
FAIL = "fail"
NOT_TESTED = "not_tested"
PENDING = "pending"
UNDEFINED = "undefined"
NOT_APPLICABLE = "not_applicable"
# 阻塞：前置条件不满足（上一阶段失败、缺少必要配置或证据），本次未执行且不能算通过。
BLOCKED = "blocked"

#: `blocked` 的枚举原因（规格 §2.3 + Q12 增补，14 个值，分四个来源侧）。
#: 写 `blocked` 时必须带其中之一，否则一律按"未测试"处理——不允许"卡住了但说不出为什么"。
BLOCKER_REASONS = frozenset(
    {
        # 平台侧
        "injection_point_missing",
        "executor_not_implemented_for_adapter",
        "payload_below_declared_limit",
        "budget_exhausted",
        "gate_failed",
        "fence_conflict",
        "task_interrupted",
        "awaiting_ttl",
        "missing_dependency",
        # 平台侧：该项被判定为 L2（机器可判），但执行器还没写。
        # 与 executor_not_implemented_for_adapter 的区别：那个是"适配器不支持"，
        # 这个是"平台还没做"。必须显式落 blocked，不能伪装成 not_tested 或 pending。
        "executor_not_implemented",
        # 上游服务本身不可用（5xx / 连不上）。与 missing_dependency 的区别是归因与动作：
        # 前者是"平台缺东西，运维装一下"，后者是"供应商挂了，联系/等恢复"。
        # 混成一个值会让运维去查自己的环境、发现什么都不缺然后卡住。
        "upstream_unavailable",
        # 人工侧
        "awaiting_human",
        # 供应商侧
        "supplier_evidence_missing",
        "supplier_evidence_refused",
        # 外部时序侧
        "awaiting_billing_period",
    }
)

#: 自动项判"不适用"时必须给出的**受控**依据标记（写在 note 里，`na_basis=<token>`）。
#: 只有"协议根本没有该能力"这种确定性情形才允许自动 NA。
NA_BASIS_TOKENS = frozenset({"protocol_lacks_capability"})
NA_BASIS_PREFIX = "na_basis="


def normalise_blocker(status: str, reason: str) -> tuple[str, str]:
    """把 (status, blocker_reason) 归一成可落库的组合。

    `blocked` 必须带枚举内的原因；带了非法值或不带，就按**未测试**处理（fail-closed），
    由调用方在 note 里说明，绝不静默保留一个说不出原因的"阻塞"。
    """
    if status != BLOCKED:
        return status, ""
    token = (reason or "").strip()
    return (status, token) if token in BLOCKER_REASONS else (NOT_TESTED, "")


def normalise_auto_na(status: str, source: str, note: str) -> tuple[str, str]:
    """把自动项的"不适用"在**写入侧**归一成 pending（除非带受控依据）。

    为什么不在读取侧做就够了：`run_items` 里存 NA、报告口径是 pending，
    任何直接读表的消费者（导出、统计、后续报表）都会和报告对不上。
    靠人记住"要读 entries 不要读表"是靠不住的。原始判定写进 note。
    """
    if status != NOT_APPLICABLE or source != "auto":
        return status, note or ""
    if na_basis_of(note or ""):
        return status, note or ""
    marker = "raw_status=not_applicable；na_candidate：自动判定缺少原文依据，需人工确认"
    merged = f"{marker}；{note}" if note else marker
    return PENDING, merged[:500]


def na_basis_of(note: str) -> str:
    """从 note 里取 `na_basis=<token>`；不在受控词表内的一律当作"没有依据"。"""
    text = note or ""
    index = text.find(NA_BASIS_PREFIX)
    if index < 0:
        return ""
    rest = text[index + len(NA_BASIS_PREFIX) :].strip()
    if not rest:
        return ""
    token = re.split(r"[\s；;,，]+", rest, maxsplit=1)[0]
    return token if token in NA_BASIS_TOKENS else ""


#: 协议允许的"正常结束原因"集合（第一章 STREAM-04 与第二章 SSE-04 共用一处）。
#: 放在 standards.py 是因为 suite / standard_checks 都依赖它，避免两份口径漂移。
FINISH_REASON_WHITELIST = frozenset(
    {"stop", "end_turn", "length", "max_tokens", "tool_calls", "tool_use", "stop_sequence", "eos", "complete"}
)

#: 三级自动化的取值（权威字段 automation_level）。
L2_LEVEL, L1_LEVEL, L0_LEVEL = "L2", "L1", "L0"
AUTOMATION_LEVELS = frozenset({L2_LEVEL, L1_LEVEL, L0_LEVEL})

#: 版本内键的方案标识。
KEY_SCHEME_ITEM_KEY = "item_key"
KEY_SCHEME_LEGACY = "legacy_id"


def item_key_for(chapter: int, display_id: str) -> str:
    """版本内唯一键：`ch{N}:{原文编号}`。

    为什么不让原文编号单独当主键：第 2～4 章来自不同工作表，编号前缀理论上可能
    重名（历史数据里已出现过同前缀跨章的情况）。加上章号之后，"哪一章的哪一条"
    才唯一。原文编号本身仍是 `display_id`，报告与页面只显示它。
    """
    return f"ch{int(chapter)}:{display_id}"


def level_to_execution(level: str) -> str:
    """`execution` 是派生只读字段：只有 L2 才自动执行。"""
    return "auto" if level == L2_LEVEL else "manual"


STATUS_LABELS = {
    PASS: "通过",
    FAIL: "不通过",
    NOT_TESTED: "未测试",
    PENDING: "待确认",
    UNDEFINED: "标准未定义",
    NOT_APPLICABLE: "不适用",
    BLOCKED: "阻塞",
}

# --- 整体结论 ---------------------------------------------------------------
#: 第一章关键项：它们决定后续章节能不能跑（阶段门禁，见 tasks._gate_reason）。
#: 放在 standards 里是因为"报告第二节要显示哪些关键项没有结论"也要用同一份清单。
CRITICAL_FIRST_CHAPTER: tuple[str, ...] = (
    "NET-01",
    "NET-02",
    "NET-03",
    "REQ-01",
    "REQ-02",
    "STREAM-01",
    "AUTH-01",
)

#: 前置必测（2026-10-30 平台新增）：优先执行，任一不通过即判不达标、后续测试不再执行。
#: 顺序即执行顺序：先确认能调通，再看缓存命中率，最后量延时分布。
PRE_GATE_IDS: tuple[str, ...] = ("GATE-01", "GATE-02", "GATE-03")


def critical_without_verdict(entries: list["Entry"]) -> list[tuple[str, str, str]]:
    """关键项里**没有判定结论**的项：返回 (item_id, status, reason)。

    门禁不因此阻断（那是平台缺证据，不是被测对象不合格），但报告必须写出来——
    只塞进接口的 stop_reason，PDF 上看不到等于没写。
    """
    by_id = {entry.item.id: entry for entry in entries}
    result: list[tuple[str, str, str]] = []
    for item_id in CRITICAL_FIRST_CHAPTER:
        entry = by_id.get(item_id)
        if entry is None or entry.excluded:
            continue
        if entry.status in {PASS, FAIL}:
            continue
        result.append((item_id, entry.status, entry.reason or entry.actual or ""))
    return result


VERDICT_PASS = "达标"
VERDICT_FAIL = "不达标"
VERDICT_UNDECIDED = "无法判定"
VERDICT_PARTIAL = "部分完成，待人工确认"

EDITABLE_REQUIREMENTS = {"mandatory", "conditional"}


class StandardsError(ValueError):
    """Raised for invalid standard edits; carries a user-facing message."""


@dataclass
class Item:
    id: str
    name: str
    chapter: int
    section: str
    scenario: str
    purpose: str
    purpose_basis: str
    chapter_goal: str
    method: str
    expected: str
    criteria: str
    execution: str
    auto_check: str | None
    requirement: str
    enabled: bool = True
    params: dict[str, str] = field(default_factory=dict)
    param_defs: list[dict[str, str]] = field(default_factory=list)
    source_table: str = ""
    expected_note: str = ""
    #: 权威分级：L2（机器可判）/ L1（机器证伪 + 人证真）/ L0（纯人工）。
    #: None 只出现在 B0.5b 之前的历史版本——历史数据不推断级别（推断不能冒充记录）。
    automation_level: str | None = None
    #: 原文编号，给人看（`MSG-01`）。item_id 在 item_key 方案下是内部键（`ch2:MSG-01`）。
    display_id: str = ""
    #: 唯一键。历史版本为空（= 用 item_id 做键）；新版本为 `ch{N}:{id}`。
    item_key: str = ""
    #: 版本内展示顺序，落库快照。历史版本迁移时由包内定义顺序回填。
    order_index: int = 0

    @property
    def is_auto(self) -> bool:
        """**唯一**允许用来判断"是否自动执行"的入口。

        有 level 时看 level（L2 才是自动）；无 level 时退回 execution（历史版本）。
        禁止散落各处写 `item.execution == "auto"`——L1/L0 一旦被当成 auto，
        就会在没有执行器的情况下被"跑"出假的通过。
        """
        if self.automation_level:
            return self.automation_level == L2_LEVEL
        return self.execution == "auto"

    @property
    def key(self) -> str:
        """落库/关联用的键：新版本用 item_key，历史版本退回 item_id。"""
        return self.item_key or self.id

    def missing_params(self) -> list[str]:
        return [d["label"] for d in self.param_defs if not str(self.params.get(d["key"], "")).strip()]

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "chapter": self.chapter,
            "section": self.section,
            "scenario": self.scenario,
            "purpose": self.purpose,
            "purpose_basis": self.purpose_basis,
            "chapter_goal": self.chapter_goal,
            "method": self.method,
            "expected": self.expected,
            "criteria": self.criteria,
            "execution": self.execution,
            "automation_level": self.automation_level,
            "auto_check": self.auto_check,
            "requirement": self.requirement,
            "enabled": self.enabled,
            "params": self.params,
            "param_defs": self.param_defs,
            "source_table": self.source_table,
            "expected_note": self.expected_note,
            # 下面三个字段进 payload：报告/接口要显示 display_id，迁移要能派生出
            # chapter 与 item_key，排序要用 order_index。缺了它们只能回头猜。
            "display_id": self.display_id or self.id,
            "item_key": self.item_key,
            "order_index": self.order_index,
        }


@dataclass
class Version:
    id: int
    standard_id: str
    version: str
    checksum: str
    item_count: int
    source_document: str
    created_at: str
    created_by: str
    note: str
    parent_id: int | None
    items: dict[str, Item]
    #: 章节结构快照，创建版本时写死。报告只读它，不读当前 config 文件。
    chapters: list[dict[str, Any]] = field(default_factory=list)
    #: definition = 创建时即快照；backfill = 迁移时回填（报告须声明标题可能不符当年）
    chapters_source: str = "backfill"
    #: legacy_id / item_key，见 KEY_SCHEME_*
    key_scheme: str = KEY_SCHEME_LEGACY

    def ordered_items(self) -> list[Item]:
        """按版本内快照顺序返回。

        只认 ``order_index``（落库快照），不再回头读当前定义文件的 enumerate 下标：
        旧实现在排序时用 `rank.get(id, 9999)` 兜底，于是"从文件里删掉/改名的项"
        会被静默排到末尾——历史报告的明细顺序会跟着当前文件漂移。
        """
        return sorted(self.items.values(), key=lambda item: (item.order_index, item.id))

    def chapter_titles(self) -> dict[int, str]:
        """章节号 → 标题，来自本版本的快照。"""
        titles: dict[int, str] = {}
        for chapter in self.chapters:
            try:
                no = int(chapter.get("no"))
            except (TypeError, ValueError):
                continue
            titles[no] = str(chapter.get("title") or f"第{no}章")
        return titles

    def chapters_backfilled(self) -> bool:
        return self.chapters_source == "backfill"


def definition() -> dict[str, Any]:
    """The shipped definition (never mutated at runtime).

    第一章与第 2～4 章分别维护在两个文件里：前者由 ``build/gen_standards_ch1.py``
    生成，后者由 ``build/gen_standards.py`` 从 Word 内嵌表格生成。这里按章节顺序
    合并，使判定、页面与 PDF 报告使用同一份快照。
    """
    parts = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in DEFINITION_PATHS
        if path.is_file()
    ]
    if not parts:
        raise FileNotFoundError("测试标准定义文件缺失：config/standards_ch1.json / standards_ch234.json")
    if len(parts) == 1:
        return parts[0]
    chapters: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    for part in parts:
        chapters.extend(part.get("chapters", []))
        items.extend(part.get("items", []))
    return {
        **MERGED_META,
        "source_document": parts[0].get("source_document", ""),
        "chapters": sorted(chapters, key=lambda chapter: chapter.get("no", 0)),
        "items": items,
    }


def shipped_chapters() -> list[dict[str, Any]]:
    """包内定义的章节列表（深拷贝），用于写入版本快照。

    只允许在"创建版本"的路径上调用；报告与页面一律读 `standard_versions.chapters`。
    """
    return json.loads(json.dumps(definition().get("chapters", []), ensure_ascii=False))


def _checksum(items: Iterable[Item]) -> str:
    payload = json.dumps(
        [item.as_payload() for item in items],
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _require_level(raw: dict[str, Any]) -> str:
    """取 automation_level：**必填、无默认**；与 execution 矛盾则拒绝加载。

    为什么不能给默认值：任何默认（尤其默认 L2）都会让漏配项**自动执行**，
    那是新造一种假绿——"没配级别"和"配成 L2"是完全不同的两件事。
    """
    item_id = raw.get("id", "?")
    level = raw.get("automation_level")
    if level is None or str(level).strip() == "":
        raise StandardsError(f"automation_level_missing: {item_id} 缺少 automation_level（必填，无默认）")
    level = str(level).strip()
    if level not in AUTOMATION_LEVELS:
        raise StandardsError(f"automation_level_invalid: {item_id} 的 automation_level={level!r} 不在 L2/L1/L0 内")
    declared = raw.get("execution")
    if declared is not None and str(declared) != level_to_execution(level):
        raise StandardsError(
            f"level_execution_mismatch: {item_id} automation_level={level} 应派生 execution="
            f"{level_to_execution(level)}，但数据里写的是 {declared!r}"
        )
    return level


def items_from_definition() -> list[Item]:
    """Build the item list exactly as shipped (no local edits applied)."""
    spec = definition()
    return [
        Item(
            id=raw["id"],
            name=raw["name"],
            chapter=raw["chapter"],
            section=raw["section"],
            scenario=raw.get("scenario", raw["name"]),
            purpose=raw.get("purpose", ""),
            purpose_basis=raw.get("purpose_basis", ""),
            chapter_goal=raw.get("chapter_goal", ""),
            method=raw.get("method", ""),
            expected=raw.get("expected", ""),
            criteria=raw.get("criteria", ""),
            execution=level_to_execution(_require_level(raw)),
            auto_check=raw.get("auto_check"),
            requirement=raw.get("requirement", "mandatory"),
            enabled=True,
            params={d["key"]: "" for d in raw.get("params", [])},
            param_defs=list(raw.get("params", [])),
            source_table=raw.get("source_table", ""),
            expected_note=raw.get("expected_note", ""),
            automation_level=_require_level(raw),
            display_id=raw.get("display_id", raw["id"]),
            item_key=item_key_for(raw["chapter"], raw.get("display_id", raw["id"])),
            order_index=index,
        )
        for index, raw in enumerate(spec["items"])
    ]


def _insert_version(
    standard_id: str,
    version: str,
    source_document: str,
    items: list[Item],
    parent_id: int | None,
    created_by: str,
    note: str,
    key_scheme: str = KEY_SCHEME_ITEM_KEY,
    chapters: list[dict[str, Any]] | None = None,
    chapters_source: str = "definition",
) -> int:
    with connect() as conn:
        cursor = conn.execute(
            """INSERT INTO standard_versions
               (standard_id, version, source_document, item_count, checksum, parent_id,
                created_by, created_at, note, key_scheme, chapters, chapters_source)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                standard_id,
                version,
                source_document,
                len(items),
                _checksum(items),
                parent_id,
                created_by,
                now_iso(),
                note,
                key_scheme,
                json.dumps(chapters if chapters is not None else shipped_chapters(), ensure_ascii=False),
                chapters_source,
            ),
        )
        version_id = int(cursor.lastrowid)
        _write_items(conn, version_id, items)
        # 硬断言检查点随版本冻结（9 行 / 5 分母）。它们是标准数据的一部分，
        # 不跟版本一起快照，历史报告就会读到"今天的"检查点。
        from .checkpoints import sync_checkpoints

        sync_checkpoints(conn, version_id)
    return version_id


def ensure_seed_version() -> int:
    """Create version 1 from the shipped definition when the table is empty."""
    with connect() as conn:
        row = conn.execute("SELECT id FROM standard_versions ORDER BY id LIMIT 1").fetchone()
        if row:
            return int(row["id"])
    spec = definition()
    items = items_from_definition()
    # 首个版本直接采用包内声明的版本号（它是这批标准数据的发布标签），
    # 之后任何自动/人工新版本都走 max(N)+1，绝不重复使用已存在的标签。
    return _insert_version(
        spec["standard_id"],
        spec["version"],
        spec["source_document"],
        items,
        None,
        "system",
        "由 config/standards_ch1.json 与 standards_ch234.json 初始导入",
    )


def sync_definition() -> int | None:
    """Bring an existing installation up to date with the shipped definition.

    仅当"最新版本由系统自动创建、且与包内定义不一致"时才追加一个新版本；
    用户手工保存过的版本一律不动，保证历史批次与其报告的标准快照不被改写。
    """
    latest_row = None
    with connect() as conn:
        latest_row = conn.execute("SELECT * FROM standard_versions ORDER BY id DESC LIMIT 1").fetchone()
    if latest_row is None:
        ensure_seed_version()
        return current_version_id()

    shipped = items_from_definition()
    shipped_checksum = _checksum(shipped)
    if latest_row["checksum"] == shipped_checksum:
        return None
    if latest_row["created_by"] != "system":
        return None

    spec = definition()
    # 标签必须是 max(N)+1，不能直接用 spec["version"]：包内声明的是"这批数据的版本"，
    # 不是"下一个可用标签"。直接复用会在第二次同步时撞 (standard_id, version) 唯一索引。
    parent = get_version(int(latest_row["id"]))
    label = _next_version_label(parent) if parent else spec["version"]
    return _insert_version(
        spec["standard_id"],
        label,
        spec["source_document"],
        shipped,
        int(latest_row["id"]),
        "system",
        f"包内标准定义更新：自动检查项由 {len(spec['items'])} 项定义同步（校验 {shipped_checksum}）",
    )


def sync_from_definition(actor: str = "system") -> int | None:
    """管理员显式触发：把**包内**标准定义同步成一个新版本。

    :func:`sync_definition` 只在"最新版本由系统创建"时才自动追加，目的是不覆盖人工保存的
    标准版本。但这带来一个升级死角：如果最新版本恰好是管理员手工另存的，包内定义变了也不会
    自动同步，页面就一直停在旧定义上（2026-10-30 升级后看不到前置必测 GATE-01~03 就是这个原因）。

    这个入口由管理员显式点按钮触发：父版本仍指向最新版本，新版本内容完全来自包内定义，
    ``created_by`` 记 ``system``，让后续升级恢复自动同步。定义已一致时返回 None。
    """
    with connect() as conn:
        latest = conn.execute("SELECT * FROM standard_versions ORDER BY id DESC LIMIT 1").fetchone()
    if latest is None:
        return ensure_seed_version()

    shipped = items_from_definition()
    checksum = _checksum(shipped)
    if latest["checksum"] == checksum:
        return None

    spec = definition()
    parent = get_version(int(latest["id"]))
    label = _next_version_label(parent) if parent else spec["version"]
    return _insert_version(
        spec["standard_id"],
        label,
        spec["source_document"],
        shipped,
        int(latest["id"]),
        "system",
        f"管理员 {actor} 触发：按包内标准定义同步（{len(shipped)} 项，校验 {checksum}）",
    )


def _write_items(conn, version_id: int, items: Iterable[Item]) -> None:
    for item in items:
        payload = item.as_payload()
        payload.pop("enabled", None)
        payload.pop("params", None)
        conn.execute(
            """INSERT INTO standard_items
               (version_id, item_id, payload, enabled, requirement, params,
                chapter, display_id, item_key, order_index)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                version_id,
                item.key,
                json.dumps(payload, ensure_ascii=False),
                1 if item.enabled else 0,
                item.requirement,
                json.dumps(item.params, ensure_ascii=False),
                item.chapter,
                item.display_id or item.id,
                item.item_key,
                item.order_index,
            ),
        )


def list_versions() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            """SELECT id, standard_id, version, source_document, item_count, checksum,
                      parent_id, created_by, created_at, note
               FROM standard_versions ORDER BY id DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


def current_version_id() -> int | None:
    with connect() as conn:
        row = conn.execute("SELECT id FROM standard_versions ORDER BY id DESC LIMIT 1").fetchone()
    return int(row["id"]) if row else None


def get_version(version_id: int) -> Version | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM standard_versions WHERE id=?", (version_id,)).fetchone()
        if row is None:
            return None
        item_rows = conn.execute(
            "SELECT item_id, payload, enabled, requirement, params, chapter, display_id, "
            "item_key, order_index FROM standard_items WHERE version_id=? ORDER BY order_index, rowid",
            (version_id,),
        ).fetchall()
    items: dict[str, Item] = {}
    for position, item_row in enumerate(item_rows):
        payload = json.loads(item_row["payload"])
        # dict 键**必须**是原文编号（payload["id"]），不是 item_id 列：
        # item_key 方案下 item_id 存的是 `ch2:MSG-01`，而 record_case_item、
        # _gate_reason、resolve_entries 都按原文编号取项。用 item_id 做键会让
        # 新版本的项全部"查不到"，表现为一连串 not_tested。
        original_id = str(payload.get("id") or item_row["item_id"])
        order_index = int(item_row["order_index"] or position)
        items[original_id] = Item(
            id=original_id,
            name=payload["name"],
            chapter=int(item_row["chapter"] or payload.get("chapter") or 0),
            section=payload["section"],
            scenario=payload.get("scenario", payload["name"]),
            purpose=payload.get("purpose", ""),
            purpose_basis=payload.get("purpose_basis", ""),
            chapter_goal=payload.get("chapter_goal", ""),
            method=payload.get("method", ""),
            expected=payload.get("expected", ""),
            criteria=payload.get("criteria", ""),
            execution=payload.get("execution", "manual"),
            automation_level=payload.get("automation_level"),
            display_id=str(item_row["display_id"] or payload.get("display_id") or original_id),
            item_key=str(item_row["item_key"] or payload.get("item_key") or ""),
            order_index=order_index,
            auto_check=payload.get("auto_check"),
            requirement=item_row["requirement"],
            enabled=bool(item_row["enabled"]),
            params=json.loads(item_row["params"] or "{}"),
            param_defs=list(payload.get("param_defs", [])),
            source_table=payload.get("source_table", ""),
            expected_note=payload.get("expected_note", ""),
        )
    return Version(
        id=int(row["id"]),
        standard_id=row["standard_id"],
        version=row["version"],
        checksum=row["checksum"],
        item_count=int(row["item_count"]),
        source_document=row["source_document"],
        created_at=row["created_at"],
        created_by=row["created_by"],
        note=row["note"],
        parent_id=row["parent_id"],
        items=items,
        chapters=_parse_chapters(row["chapters"]),
        chapters_source=str(row["chapters_source"] or "backfill"),
        key_scheme=str(row["key_scheme"] or KEY_SCHEME_LEGACY),
    )


def _parse_chapters(raw: Any) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return [dict(row) for row in parsed if isinstance(row, dict)]


def _next_version_label(parent: Version) -> str:
    """下一个版本标签：`YYYY.MM.DD-{N}`，N = 同 standard_id 的最大 N + 1。

    **不能用 COUNT(*)+1**：库里一旦有条重复标签（历史遗留），COUNT 会小于实际最大值，
    于是继续产出已存在的标签；而旧 schema 没有 (standard_id, version) 唯一约束，
    撞了也不报错——两行同标签、不同 checksum，"版本不可变"就废了。
    """
    with connect() as conn:
        rows = conn.execute(
            "SELECT version FROM standard_versions WHERE standard_id=?", (parent.standard_id,)
        ).fetchall()
    return _next_label_from([str(row["version"] or "") for row in rows])


def _next_label_from(labels: list[str]) -> str:
    """纯函数：由现有标签算出下一个标签（便于用"含重复"的历史数据自检）。

    取 max(N)+1 而不是 COUNT+1：库内存在重复标签时 COUNT 会小于实际最大值，
    于是继续产出已存在的标签。标签撞车在加唯一索引前是静默的。
    """
    max_n = 0
    for label in labels:
        suffix = label.rsplit("-", 1)[-1] if "-" in label else ""
        if suffix.isdigit():
            max_n = max(max_n, int(suffix))
    return f"{now_iso()[:10].replace('-', '.')}-{max_n + 1}"


def create_version(
    parent_id: int,
    edits: list[dict[str, Any]],
    username: str,
    note: str = "",
) -> Version:
    """Copy ``parent_id`` into a new immutable version and apply edits.

    Only whitelisted fields can change: enabled flag, requirement level and the
    numeric parameters declared by the original document for that item.  Test
    methods, criteria and章节归属 are 原文标准, 不提供修改入口。
    """
    parent = get_version(parent_id)
    if parent is None:
        raise StandardsError("父版本不存在")

    by_id = {edit.get("item_id"): edit for edit in edits}
    unknown = [item_id for item_id in by_id if item_id not in parent.items]
    if unknown:
        raise StandardsError(f"未知测试项：{', '.join(str(x) for x in unknown[:5])}")

    items: list[Item] = []
    for position, item in enumerate(parent.ordered_items()):
        clone = Item(**{**item.__dict__})
        clone.params = dict(item.params)
        # 新版本一律切到 item_key 方案：`ch{N}:{原文编号}`。
        # 历史版本（legacy_id）创建的父子关系不变，但新版本自己带完整键，
        # 避免"同样是新版本，一半有键一半没键"的中间态。
        clone.display_id = item.display_id or item.id
        clone.item_key = item_key_for(item.chapter, clone.display_id)
        clone.order_index = position
        edit = by_id.get(item.id)
        if edit:
            if "enabled" in edit:
                clone.enabled = bool(edit["enabled"])
            if "requirement" in edit:
                requirement = str(edit["requirement"])
                if requirement not in EDITABLE_REQUIREMENTS:
                    raise StandardsError(f"{item.id} 的必测级别不合法：{requirement}")
                clone.requirement = requirement
            if "params" in edit:
                params = edit["params"] or {}
                if not isinstance(params, dict):
                    raise StandardsError(f"{item.id} 的参数必须是键值对象")
                allowed = {d["key"] for d in item.param_defs}
                for key, value in params.items():
                    if key not in allowed:
                        raise StandardsError(f"{item.id} 不支持参数 {key}")
                    text = str(value).strip()
                    if text == "":
                        clone.params[key] = ""
                        continue
                    if len(text) > 32:
                        raise StandardsError(f"{item.id} 的参数 {key} 过长")
                    try:
                        number = float(text)
                    except ValueError as exc:
                        raise StandardsError(f"{item.id} 的参数 {key} 必须是数字") from exc
                    if number < 0:
                        raise StandardsError(f"{item.id} 的参数 {key} 不能为负数")
                    clone.params[key] = text
        items.append(clone)

    if not any(item.enabled for item in items):
        raise StandardsError("至少需要启用一个测试项")

    checksum = _checksum(items)
    label = _next_version_label(parent)
    version_id = _insert_version(
        parent.standard_id,
        label,
        parent.source_document,
        items,
        parent.id,
        username,
        note[:200],
        key_scheme=KEY_SCHEME_ITEM_KEY,
        # 章节快照随版本继承：父版本是回填值，子版本仍是回填值（口径不能因为
        # "又存了一次"就变成 definition）。
        chapters=parent.chapters or shipped_chapters(),
        chapters_source=parent.chapters_source,
    )
    result = get_version(version_id)
    assert result is not None
    return result


# ---------------------------------------------------------------------------
# 判定
# ---------------------------------------------------------------------------
@dataclass
class Entry:
    item: Item
    status: str
    source: str
    actual: str
    evidence: str
    note: str
    operator: str
    updated_at: str
    excluded: bool = False
    reason: str = ""
    blocker_reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item.id,
            # 显示路径一律用 display_id（`MSG-01`）；item_key（`ch2:MSG-01`）只在库里
            # 做唯一性，不进报告——报告编号是给评审方对原文用的。
            "display_id": self.item.display_id or self.item.id,
            "item_key": self.item.key,
            "name": self.item.name,
            "chapter": self.item.chapter,
            "section": self.item.section,
            "requirement": self.item.requirement,
            "execution": self.item.execution,
            "automation_level": self.item.automation_level,
            "enabled": self.item.enabled,
            "expected": self.item.expected,
            "criteria": self.item.criteria,
            "method": self.item.method,
            "status": self.status,
            "status_label": STATUS_LABELS.get(self.status, self.status),
            "source": self.source,
            "actual": self.actual,
            "evidence": self.evidence,
            "note": self.note,
            "operator": self.operator,
            "updated_at": self.updated_at,
            "excluded": self.excluded,
            "reason": self.reason,
        }


def load_run_items(run_id: int) -> dict[str, dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM run_items WHERE run_id=?", (run_id,)).fetchall()
    return {row["item_id"]: dict(row) for row in rows}


#: 允许**自动项**判"不适用"的原文依据（键=用例编号，值=原文条款）。
#:
#: 只有原文自己写了"不支持时明确拒绝或按已说明的规则转换"这类分支，机器才能
#: 合法地判"不适用"。除此之外的自动 NA 一律降级为 pending（na_candidate），
#: 由人确认——否则"上游对这类请求一律 400"就能让 12 个测试项从分母消失，
#: 结论照旧写"达标"（差距审计 K1/F8）。
#: 当前为空：MSG-05 已按 Q10 改为"明确拒绝即 pass"的三态判定，不再走 NA。
#: 需要新增时，优先在检查器里用 note 写 `na_basis=protocol_lacks_capability`，
#: 只有"协议根本没有该能力"这种确定性情形才允许自动 NA。
AUTO_NA_BASIS: dict[str, str] = {}


def auto_na_basis(case_id: str) -> str:
    """返回该用例判"不适用"的原文依据；空串表示没有依据。"""
    return AUTO_NA_BASIS.get(case_id, "")


def resolve_entries(version: Version, run_items: dict[str, dict[str, Any]]) -> list[Entry]:
    """Merge the immutable standard with what actually happened in this run.

    * 未启用 → 不参与判定；
    * 标记"不适用" → 只有**人工**标记、或原文明确给了分支依据的自动项才真正豁免，
      其余自动 NA 降级为"待确认（na_candidate）"，不得从分母消失；
    * 需要供应商参数的项在参数未配置时一律为"标准未定义"，不因曾经填过结论而放过；
    * 没有任何记录的项 → 未测试（绝不默认通过）。
    """
    entries: list[Entry] = []
    for item in version.ordered_items():
        record = run_items.get(item.id) or {}
        status = str(record.get("status") or NOT_TESTED)
        entry = Entry(
            item=item,
            status=status,
            source=str(record.get("source") or ("auto" if item.is_auto else "manual")),
            actual=str(record.get("actual") or ""),
            evidence=str(record.get("evidence") or ""),
            note=str(record.get("note") or ""),
            operator=str(record.get("operator") or ""),
            updated_at=str(record.get("updated_at") or ""),
        )
        if not item.enabled:
            entry.excluded = True
            entry.reason = "该测试项在本标准版本中未启用"
        elif status == NOT_APPLICABLE:
            basis = auto_na_basis(item.id) if entry.source == "auto" else ""
            if entry.source == "auto":
                # 受控依据标记（note 里的 na_basis=<token>）优先于静态白名单。
                basis = na_basis_of(entry.note) or basis
            if entry.source == "auto" and not basis:
                # K1：自动项不得自行把"没验过"变成"不适用"。
                entry.status = PENDING
                entry.reason = (
                    "自动判定为不适用，但原文没有给出该分支的依据（na_candidate），"
                    "需人工确认是否真的不适用"
                )
            else:
                entry.excluded = True
                # K2：归因不能说谎——自动项不能说成"人工标记"。
                if basis:
                    entry.reason = f"自动判定为不适用，原文依据：{basis}"
                else:
                    entry.reason = entry.note or "人工标记为不适用"
        elif status in {BLOCKED, NOT_TESTED}:
            entry.blocker_reason = str(record.get("blocker_reason") or "")
            if status == BLOCKED:
                entry.status, entry.blocker_reason = normalise_blocker(status, entry.blocker_reason)
                if entry.status != BLOCKED:
                    entry.reason = "记录为阻塞但缺少 blocker_reason 枚举值，按未测试处理（平台缺陷）"
        else:
            missing = item.missing_params()
            if missing:
                entry.status = UNDEFINED
                entry.reason = "标准未定义：原文要求按供应商/模型配置 " + "、".join(missing) + "，当前未配置"
            elif status not in STATUS_LABELS:
                entry.status = NOT_TESTED
                entry.reason = f"未知状态 {status}，按未测试处理"
        entries.append(entry)
    return entries


def conclusion(entries: list[Entry]) -> dict[str, Any]:
    """Overall verdict per the task rules.

    1. 任一适用项不通过 → 不达标（优先于其它状态）
    2. 存在未测试 / 阻塞 / 标准未定义 → 无法判定（没有执行证据，不能判达标）
    3. 自动项全部通过、仅剩待人工确认 → 部分完成，待人工确认
    4. 全部适用必测项通过 → 达标
    """
    applicable = [e for e in entries if not e.excluded]
    counts: dict[str, int] = {key: 0 for key in STATUS_LABELS}
    for entry in applicable:
        counts[entry.status] = counts.get(entry.status, 0) + 1
    excluded = len(entries) - len(applicable)

    failed = [e for e in applicable if e.status == FAIL]
    pending = [e for e in applicable if e.status == PENDING]
    unexecuted = [e for e in applicable if e.status in {NOT_TESTED, BLOCKED, UNDEFINED}]
    passed = [e for e in applicable if e.status == PASS]

    if failed:
        verdict = VERDICT_FAIL
        reason = f"{len(failed)} 项不通过"
    elif unexecuted:
        verdict = VERDICT_UNDECIDED
        parts = []
        for key in (NOT_TESTED, BLOCKED, UNDEFINED):
            if counts[key]:
                parts.append(f"{STATUS_LABELS[key]} {counts[key]} 项")
        reason = "存在" + "、".join(parts)
    elif pending:
        verdict = VERDICT_PARTIAL
        reason = f"自动测试已完成，仍有 {len(pending)} 项待人工确认"
    elif applicable and len(passed) == len(applicable):
        verdict = VERDICT_PASS
        reason = "全部适用必测项通过"
    else:
        verdict = VERDICT_UNDECIDED
        reason = "没有可判定的测试项"

    return {
        "verdict": verdict,
        "reason": reason,
        "total": len(entries),
        "applicable": len(applicable),
        "excluded": excluded,
        "counts": counts,
        "passed": len(passed),
        "failed": len(failed),
        "pending": len(pending),
        "blocking": len(unexecuted),
    }


def report_number(run_id: int, created_at: str) -> str:
    date = (created_at or now_iso())[:10].replace("-", "")
    return f"RPT-{date}-{run_id:03d}"
