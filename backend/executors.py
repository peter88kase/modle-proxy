"""执行器台账：L2 项里哪些真的能跑，哪些还只是"判得了但还没写"。

为什么要有这份台账
------------------
把某项判成 L2（机器可判）和"平台已经有代码能判它"是两件事。上一版把两者混为
一谈：配置说 auto，执行器不存在，运行时既不报错也不落 blocked，最后在报告里
落成"未测试"，看起来像"上游没响应"，实际是"平台没实现"。这份台账把缺口写成
数据，运行时据此落 `blocked(executor_not_implemented)`，报告据此显示就绪率。

字段口径
--------
* `batch`：计划在哪一批补上。文档里有明确批次的写批次号（见 docs/10 §8.2、
  docs/12 §8.3），**没有排期的写 `unassigned`**——不许编一个批次糊过去。
* `reason`：为什么现在没有。取值见 `PENDING_REASONS`，报告里按这个分类展示。
* `critical`：是否第一章关键项（决定后续章节门禁）。第 2～4 章一律 False。
* `mandatory`：是否原文必测项（条件项不计入必测统计，但仍要跑）。

三条自检（`tests/test_executor_registry.py`）：
1. 每个"L2 且无执行器"的项必须在台账里；
2. 台账里的每一项必须真的存在、真的是 L2、真的没有执行器（不留过期条目）；
3. 台账里的 reason 必须在受控词表内——否则"为什么没实现"又会退化成自由文本。
"""

from __future__ import annotations

from typing import Any

from .standards import CRITICAL_FIRST_CHAPTER, Item, L2_LEVEL

#: 第 1 章的自动项由验收套件（suite.py 的 case_id）执行，不需要 standard_checks。
SUITE_EXECUTED_CHAPTERS = (1,)

#: 未实现原因的受控词表。新增值必须同时更新报告文案，否则报告会显示原始英文码。
PENDING_REASONS: dict[str, str] = {
    "missing_param_construction": "缺「参数录入 → 自动构造」联动（参数缺失时应判未定义，参数就位后自动生成请求）",
    "missing_injection_point": "缺可注入故障/异常事件的模拟上游（mid-stream error、未知事件）",
    "missing_fixture": "缺受控测试素材（平台自建图床 / 固定样本文件）",
    "missing_long_run": "缺长任务能力（等待 N 分钟 + 期间禁止访问同一前缀的隔离约束）",
    "missing_snapshot": "缺转发体快照与逐次上游尝试落库",
    "missing_executor": "执行器尚未编写；docs/10 §8.2 的六项能力都不覆盖它，需要单独排期",
}

#: 逐项台账。键是**原文编号**（display_id），不是 ch{N}:{id}。
#: 键用原文编号是因为报告、页面、人工复核都按原文编号对表；item_key 只在库里做唯一性。
PENDING_EXECUTORS: dict[str, dict[str, Any]] = {
    # --- B4 参数录入 → 自动构造（docs/10 §8.2 第 1 项） -------------------
    "CACHE-01": {"batch": "B4", "reason": "missing_param_construction",
                 "why": "首次写入需按声明的缓存机制与粒度构造可缓存前缀"},
    "CACHE-05": {"batch": "B4", "reason": "missing_param_construction",
                 "why": "低于门槛需知道最小可缓存长度，参数未录入时无法构造"},
    "TTL-01": {"batch": "B4", "reason": "missing_param_construction",
               "why": "有效期内读取需按声明的 TTL 值安排第二次请求"},
    "LIMIT-02": {"batch": "B4", "reason": "missing_param_construction",
                 "why": "分档输入需按声明的上下文上限与输出上限分档构造"},
    "LIMIT-04": {"batch": "B4", "reason": "missing_param_construction",
                 "why": "最大输出参数需按声明上限取值并核对完成原因"},
    "LIMIT-05": {"batch": "B4", "reason": "missing_param_construction",
                 "why": "长输出生成需按声明上限构造 token 预算，属长耗时请求"},
    "MEDIA-06": {"batch": "B4", "reason": "missing_param_construction",
                 "why": "「不支持视觉的模型」需按能力矩阵选模型，未录入时无法构造"},
    "ERR-05": {"batch": "B4", "reason": "missing_param_construction",
               "why": "「不支持的能力」需按能力矩阵挑一项供应商明确不支持的能力再发请求"},
    # --- B4 清单遍历型执行器（docs/10 §8.2 第 2 项） ----------------------
    "CAP-03": {"batch": "B4", "reason": "missing_fixture",
               "why": "视觉能力需平台自建图床生成含随机串的 PNG（docs/10 §8.2 第 3 项）"},
    "CAP-04": {"batch": "B4", "reason": "missing_param_construction",
               "why": "工具调用能力核验需按能力矩阵逐项遍历，且要工具桩与第二轮回传值比对"},
    "CAP-05": {"batch": "B4", "reason": "missing_param_construction",
               "why": "结构化输出能力核验需按声明的 schema 支持度遍历"},
    # --- B6 长任务与隔离（docs/12 §8.3） ---------------------------------
    "TTL-02": {"batch": "B6", "reason": "missing_long_run",
               "why": "到期后访问需真实等待 TTL，且等待期禁止访问同一前缀（p174 硬要求）"},
    "TTL-03": {"batch": "B6", "reason": "missing_long_run",
               "why": "命中续期需跨两个 TTL 窗口观察，属长时任务"},
    "CONS-01": {"batch": "B6", "reason": "missing_long_run",
                "why": "不同时段一致性需跨批次调度（B6 sampling_observations）"},
    # --- B5 模拟上游 / 图床 -------------------------------------------------
    "MEDIA-01": {"batch": "B5", "reason": "missing_fixture",
                 "why": "图片 URL 需公网可达的受控图床（docs/10 §8.2 第 3 项）"},
    "SSE-03": {"batch": "B5", "reason": "missing_injection_point",
               "why": "多内容块需模拟上游按固定顺序注入多个内容块事件"},
    "CONV-03": {"batch": "B5", "reason": "missing_snapshot",
                "why": "不可转换能力需比对转发前后请求体，当前只落最终结果"},
    # --- 未排期：docs/10 §8.2 六项能力都不覆盖 -----------------------------
    "MEDIA-04": {"batch": "unassigned", "reason": "missing_fixture",
                 "why": "图文混合需受控图片素材 + 文本标记同时回显"},
    "THINK-01": {"batch": "unassigned", "reason": "missing_executor",
                 "why": "思考开关需按供应商字段名（thinking/reasoning）分支构造"},
    "THINK-02": {"batch": "unassigned", "reason": "missing_executor",
                 "why": "思考预算需按声明的预算参数构造并核对 usage 中的推理 token"},
    "THINK-03": {"batch": "unassigned", "reason": "missing_executor",
                 "why": "内容块处理需判定思考块与正文块的顺序与类型"},
    "THINK-04": {"batch": "unassigned", "reason": "missing_executor",
                 "why": "多轮回传需把思考块原样回传并观察是否被拒绝"},
    "CACHE-03": {"batch": "unassigned", "reason": "missing_executor",
                 "why": "连续读取需多次请求同一前缀并逐次比对 cached_tokens"},
    "CACHE-04": {"batch": "unassigned", "reason": "missing_executor",
                 "why": "回答正确性需固定问答对做语义比对，缺样本库"},
    "PREFIX-01": {"batch": "unassigned", "reason": "missing_executor",
                  "why": "后缀变化需成对构造「同前缀不同后缀」两次请求"},
    "PREFIX-04": {"batch": "unassigned", "reason": "missing_executor",
                  "why": "追加历史需按多轮结构递增 messages"},
    "PREFIX-05": {"batch": "unassigned", "reason": "missing_executor",
                  "why": "工具定义变化需比对工具 schema 变更前后的缓存命中"},
    "PREFIX-06": {"batch": "unassigned", "reason": "missing_executor",
                  "why": "内容更新生效需验证改前缀后旧缓存不得被复用"},
    "CTRL-01": {"batch": "unassigned", "reason": "missing_executor",
                "why": "缓存断点需按声明的显式缓存参数（cache_control）构造"},
    "CTRL-02": {"batch": "unassigned", "reason": "missing_executor",
                "why": "字符串与内容块两种形态需分别打断点并比对命中"},
    "CTRL-04": {"batch": "unassigned", "reason": "missing_executor",
                "why": "非法配置需构造越界/错类型的缓存参数并判「明确拒绝」"},
    "TTL-05": {"batch": "unassigned", "reason": "missing_executor",
               "why": "非法 TTL 需构造越界 TTL 并判「明确拒绝」"},
    "SCOPE-01": {"batch": "unassigned", "reason": "missing_executor",
                 "why": "切换模型需在同一前缀下换模型并观察缓存是否被误复用"},
    "MODE-01": {"batch": "unassigned", "reason": "missing_executor",
                "why": "非流式写入与读取需两次非流式请求比对缓存字段"},
    "MODE-02": {"batch": "unassigned", "reason": "missing_executor",
                "why": "流式写入与读取需从 SSE 事件里汇总缓存字段"},
    "MODE-03": {"batch": "unassigned", "reason": "missing_executor",
                "why": "跨模式复用需流式与非流式交替并比对命中"},
    "MODE-04": {"batch": "unassigned", "reason": "missing_executor",
                "why": "流式用量汇总需逐事件累加并与非流式口径对齐"},
    "CONC-01": {"batch": "unassigned", "reason": "missing_executor",
                "why": "热缓存并发需并发请求同一前缀并核对命中稳定性"},
    "BILL-05": {"batch": "unassigned", "reason": "missing_executor",
                "why": "平台扣费需与账单侧对账，属三层对账范畴（人工证据 + 机器比对）"},
    "LIMIT-03": {"batch": "unassigned", "reason": "missing_executor",
                 "why": "长内容可用性需近上限输入下的语义可用性判定，缺样本库"},
    "LIMIT-06": {"batch": "unassigned", "reason": "missing_executor",
                 "why": "超限行为需构造超上限输入并判「明确错误」"},
}

#: 台账里的每条都必须带这两个键，缺一个就说明登记不完整。
_REQUIRED_FIELDS = ("batch", "reason", "why")


def pending_spec(item: Item) -> dict[str, Any] | None:
    """该测试项是否属于"判得了但还没实现"，返回台账条目（含 critical / mandatory）。"""
    if item.automation_level != L2_LEVEL:
        return None
    if item.auto_check:
        return None
    if item.chapter in SUITE_EXECUTED_CHAPTERS:
        return None
    spec = PENDING_EXECUTORS.get(item.display_id or item.id)
    if spec is None:
        return None
    return {
        **spec,
        "critical": (item.display_id or item.id) in CRITICAL_FIRST_CHAPTER,
        "mandatory": item.requirement == "mandatory",
    }


def executor_kind(item: Item) -> str:
    """返回 `check` / `suite` / `pending` / `manual` / `missing`。

    `missing` 是配置缺陷（L2 却既无执行器又不在台账），必须能被测试抓出来；
    不要把它和 `pending` 混成一类，否则台账漏登记永远发现不了。
    """
    if not item.is_auto:
        return "manual"
    if item.auto_check:
        return "check"
    if item.chapter in SUITE_EXECUTED_CHAPTERS:
        return "suite"
    if (item.display_id or item.id) in PENDING_EXECUTORS:
        return "pending"
    return "missing"


def executor_stats(items: list[Item]) -> dict[str, Any]:
    """L2 项的执行器就绪情况（报告"就绪率"的唯一口径）。

    分母只算 L2：L1/L0 本来就不该由平台自动执行，把它们算进分母会让就绪率
    永远上不去，也会诱导实现方去"补"不该补的项。
    """
    buckets: dict[str, int] = {"check": 0, "suite": 0, "pending": 0, "missing": 0}
    pending_by_batch: dict[str, int] = {}
    mandatory_pending = 0
    l2_total = 0
    for item in items:
        if item.automation_level != L2_LEVEL:
            continue
        l2_total += 1
        kind = executor_kind(item)
        if kind not in buckets:
            kind = "missing"
        buckets[kind] += 1
        if kind == "pending":
            spec = PENDING_EXECUTORS.get(item.display_id or item.id) or {}
            batch = str(spec.get("batch") or "unassigned")
            pending_by_batch[batch] = pending_by_batch.get(batch, 0) + 1
            if item.requirement == "mandatory":
                mandatory_pending += 1
    ready = buckets["check"] + buckets["suite"]
    return {
        "l2_total": l2_total,
        "ready": ready,
        "ready_check": buckets["check"],
        "ready_suite": buckets["suite"],
        "pending": buckets["pending"],
        "missing": buckets["missing"],
        "ready_percent": round(ready * 100 / l2_total) if l2_total else 0,
        "pending_by_batch": dict(sorted(pending_by_batch.items())),
        "pending_mandatory": mandatory_pending,
    }
