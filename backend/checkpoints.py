"""硬断言检查点：9 行数据 / 5 项分母，与 166 项主分母分开计量。

原文（p118、p201 附近）那两张表**不给用例编号**。把它们硬塞进 166 项会同时
破坏两件事：① `item_count` 变 175，所有「166」口径失效；② 报告里会出现
"看起来像原文编号、其实平台自造"的编号。所以：单独建表、单独计量、显式标
`code_kind=platform_checkpoint_not_original_id`。

分母规则（`config/hard_assertions.json: denominator_policy`）：
* Claude 兼容上游：166（主分母）+ 5（本组）= **171**；
* 其他协议：166，本组 9 行仍执行落库进报告，但整组标"不适用"并给出固定理由。
  `counted=0` 的 4 条与 CLAUDE-REG-01~04 同源，已合并计量。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .config import BASE_DIR

HARD_ASSERTIONS_PATH = BASE_DIR / "config" / "hard_assertions.json"

#: 固定文案：非 Claude 渠道时整组的"不适用"理由。**不得改写、不得换成"未测试"**。
NOT_APPLICABLE_REASON = "非 Claude 兼容上游，该组硬断言不适用"

#: 原文没有给编号，平台不得伪造。所有 9 行的 code_kind 必须恰好是这一个值。
CODE_KIND = "platform_checkpoint_not_original_id"


def load_config() -> dict[str, Any]:
    if not HARD_ASSERTIONS_PATH.is_file():
        raise FileNotFoundError(f"硬断言配置缺失：{HARD_ASSERTIONS_PATH}")
    return json.loads(HARD_ASSERTIONS_PATH.read_text(encoding="utf-8"))


def checksum_of(config: dict[str, Any]) -> str:
    """配置文件自校验（去掉 checksum 字段后的整体 sha256 前 16 位）。"""
    body = {key: value for key, value in config.items() if key != "checksum"}
    payload = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def rows() -> list[dict[str, Any]]:
    """把配置翻译成落库行（9 行）。

    `chapter` 由 source_section 决定：CLAUDE-REG-01~04 出自 2.12 之后的固定回归表
    → 第 2 章；CH3-REG-01~05 出自 3.12 → 第 3 章。
    """
    config = load_config()
    counted_codes = set(config["denominator_policy"]["group_codes"])
    result: list[dict[str, Any]] = []
    for item in config["items"]:
        code = str(item["code"])
        chapter = 3 if code.startswith("CH3-REG") else 2
        result.append(
            {
                "checkpoint": f"ch{chapter}:{code}",
                "display_code": code,
                "chapter": chapter,
                "code_kind": str(item.get("code_kind") or CODE_KIND),
                "proxy_of": str(item.get("proxy_of") or ""),
                "counted": 1 if code in counted_codes else 0,
                "payload": item,
                "enabled": 1,
            }
        )
    return result


def sync_checkpoints(conn: Any, version_id: int) -> int:
    """把 9 行写进 `standard_checkpoints`（幂等）。

    每次创建版本都执行：检查点是标准数据的一部分，必须跟版本一起冻结。
    """
    written = 0
    for row in rows():
        conn.execute(
            """INSERT INTO standard_checkpoints
               (version_id, checkpoint, display_code, chapter, code_kind, proxy_of, counted,
                payload, enabled)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(version_id, checkpoint) DO UPDATE SET
                 display_code=excluded.display_code, chapter=excluded.chapter,
                 code_kind=excluded.code_kind, proxy_of=excluded.proxy_of,
                 counted=excluded.counted, payload=excluded.payload, enabled=excluded.enabled""",
            (
                version_id,
                row["checkpoint"],
                row["display_code"],
                row["chapter"],
                row["code_kind"],
                row["proxy_of"],
                row["counted"],
                json.dumps(row["payload"], ensure_ascii=False),
                row["enabled"],
            ),
        )
        written += 1
    return written


def list_checkpoints(version_id: int) -> list[dict[str, Any]]:
    from .db import connect

    with connect() as conn:
        rows_out = conn.execute(
            "SELECT checkpoint, display_code, chapter, code_kind, proxy_of, counted, enabled "
            "FROM standard_checkpoints WHERE version_id=? ORDER BY chapter, checkpoint",
            (version_id,),
        ).fetchall()
    return [dict(row) for row in rows_out]


def is_claude_channel(adapter: str, provider_id: str = "") -> bool:
    """是否 Claude 兼容上游（决定 166 还是 171）。"""
    adapter = (adapter or "").lower()
    provider_id = (provider_id or "").lower()
    return adapter in {"anthropic", "anthropic-messages", "claude"} or "claude" in provider_id


def effective_denominator(
    item_count: int, adapter: str, provider_id: str = "", counted_checkpoints: int = 5
) -> dict[str, Any]:
    """有效分母：主分母（166）+ 计入的硬断言检查点（Claude 渠道 5，其他 0）。

    非 Claude 渠道不是"少了几项"，而是整组不适用：理由固定、原样进报告，
    **不得写"未测试"**——不适用与没测是两件事，混用会让分母悄悄变小。
    """
    claude = is_claude_channel(adapter, provider_id)
    extra = counted_checkpoints if claude else 0
    return {
        "claude_channel": claude,
        "main": int(item_count),
        "checkpoints_counted": extra,
        "effective": int(item_count) + extra,
        "not_applicable_reason": "" if claude else NOT_APPLICABLE_REASON,
    }
