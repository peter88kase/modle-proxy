"""第 2～4 章的自动检查实现。

原则：只有平台能对被测端点发出真实请求、并仅凭响应（状态码/结构/文本/usage）
得出结论的测试项才实现为自动检查；无法取得判定证据的项保持人工，绝不因为
"想全部自动化"而伪造结论。

判定约定
--------
* 端点正常返回但内容不满足原文要求 → ``fail``
* 端点不可达、超时、截断 → ``not_tested``（没有证据，不能判通过也不能判失败）
* 模型明确拒绝某能力（4xx 且语义为不支持） → ``not_applicable``（原文允许显式拒绝）
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
import struct
import zlib
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import httpx

from .adapters.base import CallSpec, get_adapter
from .config import settings
from .budget import take_request
from .netguard import TargetError, validate_url
from .security import redact_text
from .standards import (
    BLOCKED,
    FAIL,
    FINISH_REASON_WHITELIST,
    NOT_APPLICABLE,
    NOT_TESTED,
    PASS,
    PENDING,
)
from .suite import SuiteConfig
from .upstream import execute

Emit = Callable[[str, dict[str, Any]], Awaitable[None]]

OPENAI_LIKE = {"openai"}
ANTHROPIC = "anthropic"
GEMINI = "gemini"

#: 当前检查项在标准里配置的供应商侧参数（context_limit_tokens 等）。
#: asyncio 每个检查在自己的 Task 里跑，ContextVar 按任务隔离，不会串项。
_ITEM_PARAMS: ContextVar[dict[str, str]] = ContextVar("item_params", default={})


def _param(key: str, default: str = "") -> str:
    return str((_ITEM_PARAMS.get() or {}).get(key, default) or "").strip()


def _int_param(key: str) -> int | None:
    raw = _param(key)
    try:
        value = int(float(raw))
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


@dataclass
class CheckResult:
    item_id: str
    status: str
    actual: str
    evidence: str
    #: `blocked` 的枚举原因（规格 §2.3）。当前检查器里产生 blocked 的两类：
    #: 适配器未实现 → executor_not_implemented_for_adapter；
    #: 上游 5xx/无响应 → missing_dependency（上游不可用，无法判定该能力）。
    blocker_reason: str = ""
    #: 自动判"不适用"时必须带的受控依据（`na_basis=protocol_lacks_capability`）。
    note: str = ""


@dataclass
class RawResult:
    status: int | None = None
    json_body: dict[str, Any] = field(default_factory=dict)
    text: str = ""
    error: str = ""
    latency_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    def error_code(self) -> str:
        err = self.json_body.get("error") if isinstance(self.json_body, dict) else None
        if isinstance(err, dict):
            return str(err.get("code") or err.get("type") or "")
        if isinstance(err, str):
            return err[:60]
        return ""

    def error_message(self) -> str:
        err = self.json_body.get("error") if isinstance(self.json_body, dict) else None
        if isinstance(err, dict):
            return str(err.get("message") or "")
        if isinstance(err, str):
            return err
        return ""


def _token(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4).upper()}"


def _brief(text: Any, limit: int = 160) -> str:
    cleaned = redact_text("" if text is None else str(text), 500).replace("\n", " ").strip()
    return cleaned[:limit] + ("…" if len(cleaned) > limit else "")


def _adapter(cfg: SuiteConfig):
    return get_adapter(cfg.adapter)


def _base_spec(
    cfg: SuiteConfig,
    *,
    system: str = "",
    prompt: str = "",
    max_tokens: int = 48,
    temperature: float | None = 0.0,
    stream: bool = False,
    stream_usage: bool = False,
    body: dict[str, Any] | None = None,
) -> CallSpec:
    return CallSpec(
        base_url=cfg.direct_base_url or cfg.forward_base_url,
        model=cfg.model,
        api_key=cfg.api_key,
        api_secret=cfg.api_secret,
        auth_style=cfg.auth_style,
        system=system,
        prompt=prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        stream=stream,
        stream_usage=stream_usage,
        extra_body={"body": body or {}},
    )


async def _call(cfg: SuiteConfig, spec: CallSpec):
    return await execute(
        _adapter(cfg),
        spec,
        total_timeout=min(cfg.total_timeout, 40),
        connect_timeout=cfg.connect_timeout,
        first_token_timeout=min(cfg.first_token_timeout, 30),
        max_bytes=settings.model_max_body_bytes,
    )


async def _post(cfg: SuiteConfig, spec: CallSpec) -> RawResult:
    """Send the adapter-built request as-is, without judging the payload."""
    allowed, reason = take_request()
    if not allowed:
        return RawResult(error=reason)
    try:
        prepared = _adapter(cfg).build(spec)
        validate_url(prepared.url, resolve=True)
    except Exception as exc:  # noqa: BLE001
        return RawResult(error=f"无法构造或校验请求：{getattr(exc, 'message', exc)}")

    headers = dict(prepared.headers)
    timeout = httpx.Timeout(min(cfg.total_timeout, 40), connect=cfg.connect_timeout)
    started = asyncio.get_event_loop().time()
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            response = await client.post(prepared.url, headers=headers, json=prepared.json_body)
    except Exception as exc:  # noqa: BLE001 - 网络异常即无证据
        return RawResult(error=_brief(exc))
    latency = int((asyncio.get_event_loop().time() - started) * 1000)
    payload: dict[str, Any] = {}
    text = response.text[:2000]
    try:
        parsed = response.json()
        if isinstance(parsed, dict):
            payload = parsed
    except ValueError:
        payload = {}
    return RawResult(status=response.status_code, json_body=payload, text=text, latency_ms=latency)


def _content_text(payload: dict[str, Any]) -> str:
    """Extract assistant text from any of the three protocol shapes."""
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                return "".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    content = payload.get("content")
    if isinstance(content, list):
        return "".join(str(block.get("text") or "") for block in content if isinstance(block, dict))
    candidates = payload.get("candidates")
    if isinstance(candidates, list) and candidates:
        parts = (candidates[0].get("content") or {}).get("parts") or []
        return "".join(str(part.get("text") or "") for part in parts if isinstance(part, dict))
    return ""


def _usage(payload: dict[str, Any]) -> dict[str, Any]:
    usage = payload.get("usage")
    if isinstance(usage, dict):
        return usage
    meta = payload.get("usageMetadata")
    return meta if isinstance(meta, dict) else {}


def _cached_tokens(payload: dict[str, Any]) -> int | None:
    """Cache-read tokens across the three protocol shapes; None if not reported."""
    usage = _usage(payload)
    details = usage.get("prompt_tokens_details")
    if isinstance(details, dict) and details.get("cached_tokens") is not None:
        try:
            return int(details["cached_tokens"])
        except (TypeError, ValueError):
            return None
    for key in ("cache_read_input_tokens", "cachedContentTokenCount", "cache_read_tokens"):
        if usage.get(key) is not None:
            try:
                return int(usage[key])
            except (TypeError, ValueError):
                return None
    return None


def _tool_calls(payload: dict[str, Any]) -> list[dict[str, Any]]:
    choices = payload.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message") or {}
        calls = message.get("tool_calls")
        if isinstance(calls, list):
            return [c for c in calls if isinstance(c, dict)]
    content = payload.get("content")
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"]
    candidates = payload.get("candidates")
    if isinstance(candidates, list) and candidates:
        parts = (candidates[0].get("content") or {}).get("parts") or []
        return [p for p in parts if isinstance(p, dict) and p.get("functionCall")]
    return []


def _messages_body(protocol: str, messages: list[dict[str, str]]) -> dict[str, Any]:
    if protocol == GEMINI:
        return {
            "contents": [
                {"role": "user" if m["role"] != "assistant" else "model", "parts": [{"text": m["content"]}]}
                for m in messages
            ]
        }
    return {"messages": messages}


# ---------------------------------------------------------------------------
# 2.3 基础消息与角色
# ---------------------------------------------------------------------------
async def check_msg_marker(cfg: SuiteConfig) -> CheckResult:
    """MSG-01：随机标记原样返回。"""
    token = _token("MSG")
    outcome = await _call(cfg, _base_spec(cfg, prompt=f"请原样输出下面这串标记，不要输出任何其他内容：{token}", max_tokens=32))
    if outcome.error_code and not outcome.text:
        return CheckResult("MSG-01", NOT_TESTED, "未能取得响应", f"请求失败：{_brief(outcome.error_message or outcome.error_code)}")
    hit = token in outcome.text
    return CheckResult(
        "MSG-01",
        PASS if hit else FAIL,
        f"返回内容{'包含' if hit else '不包含'}随机标记 {token}",
        f"HTTP {outcome.http_status}；响应片段：{_brief(outcome.text)}",
    )


async def check_msg_multiturn(cfg: SuiteConfig) -> CheckResult:
    """MSG-02：多轮对话能引用第一轮信息。"""
    token = _token("MT")
    messages = [
        {"role": "user", "content": f"请记住这串信息：{token}。只回复“已记住”。"},
        {"role": "assistant", "content": "已记住。"},
        {"role": "user", "content": "今天天气无关紧要。刚才让你记住的信息是什么？只回复那串信息。"},
    ]
    result = await _post(cfg, _base_spec(cfg, prompt="", max_tokens=48, body=_messages_body(cfg.adapter, messages)))
    if result.status is None:
        return CheckResult("MSG-02", NOT_TESTED, "请求未完成", result.error)
    if not result.ok:
        return CheckResult("MSG-02", FAIL, f"多轮请求被拒绝（HTTP {result.status}）", _brief(result.error_message() or result.text))
    text = _content_text(result.json_body)
    hit = token in text
    return CheckResult("MSG-02", PASS if hit else FAIL, f"多轮上下文{'被正确引用' if hit else '未被引用'}", f"响应片段：{_brief(text)}")


async def check_msg_assistant_history(cfg: SuiteConfig) -> CheckResult:
    """MSG-03：历史 assistant 消息被保留并使用。"""
    token = _token("AS")
    messages = [
        {"role": "user", "content": "接下来我会给你一段资料。"},
        {"role": "assistant", "content": f"资料编号为 {token}。"},
        {"role": "user", "content": "刚才的资料编号是多少？只回复编号。"},
    ]
    result = await _post(cfg, _base_spec(cfg, prompt="", max_tokens=40, body=_messages_body(cfg.adapter, messages)))
    if result.status is None:
        return CheckResult("MSG-03", NOT_TESTED, "请求未完成", result.error)
    if not result.ok:
        return CheckResult("MSG-03", FAIL, f"请求被拒绝（HTTP {result.status}）", _brief(result.error_message() or result.text))
    text = _content_text(result.json_body)
    hit = token in text
    return CheckResult("MSG-03", PASS if hit else FAIL, f"assistant 历史{'被正确使用' if hit else '丢失或未被使用'}", f"响应片段：{_brief(text)}")


async def check_system_rule(cfg: SuiteConfig) -> CheckResult:
    """MSG-04：system 指令被执行。"""
    token = _token("SYS")
    outcome = await _call(
        cfg,
        _base_spec(
            cfg,
            system=f"你只能输出 {token} 这一个字符串，不要解释、不要标点、不要换行。",
            prompt="现在开始。",
            max_tokens=32,
        ),
    )
    if outcome.error_code and not outcome.text:
        return CheckResult("MSG-04", NOT_TESTED, "未能取得响应", f"请求失败：{_brief(outcome.error_message or outcome.error_code)}")
    hit = token in outcome.text
    return CheckResult(
        "MSG-04",
        PASS if hit else FAIL,
        f"system 指定的标记{'已' if hit else '未'}出现在响应中",
        f"HTTP {outcome.http_status}；响应片段：{_brief(outcome.text)}",
    )


async def check_msg_multi_block(cfg: SuiteConfig) -> CheckResult:
    """MSG-06：同一消息内多个内容块的顺序与完整性。"""
    if cfg.adapter not in OPENAI_LIKE:
        return CheckResult("MSG-06", BLOCKED, "当前协议不支持内容块数组", "该检查目前仅实现 OpenAI Chat Completions 的内容块形式", blocker_reason="executor_not_implemented_for_adapter")
    a, b, c = _token("B1"), _token("B2"), _token("B3")
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": f"第一段标记 {a}"},
                    {"type": "text", "text": f"第二段标记 {b}"},
                    {"type": "text", "text": f"第三段标记 {c}"},
                ],
            },
            {"role": "user", "content": "按顺序原样输出上面三个标记，用空格分隔。"},
        ]
    }
    result = await _post(cfg, _base_spec(cfg, prompt="", max_tokens=60, body=body))
    if result.status is None:
        return CheckResult("MSG-06", NOT_TESTED, "请求未完成", result.error)
    if not result.ok:
        return CheckResult("MSG-06", FAIL, f"多内容块请求被拒绝（HTTP {result.status}）", _brief(result.error_message() or result.text))
    text = _content_text(result.json_body)
    positions = [text.find(t) for t in (a, b, c)]
    ordered = all(p >= 0 for p in positions) and positions == sorted(positions)
    return CheckResult(
        "MSG-06",
        PASS if ordered else FAIL,
        "三个内容块标记按顺序出现" if ordered else "内容块缺失或顺序错乱",
        f"包含情况 {[p >= 0 for p in positions]}；响应片段：{_brief(text)}",
    )


async def check_msg_string_vs_array(cfg: SuiteConfig) -> CheckResult:
    """MSG-07：字符串与内容块数组两种等价形式都能正确处理。"""
    if cfg.adapter not in OPENAI_LIKE:
        return CheckResult("MSG-07", BLOCKED, "当前协议不提供两种等价表示", "仅 OpenAI Chat Completions 同时支持字符串与内容块数组", blocker_reason="executor_not_implemented_for_adapter")
    token = _token("EQ")
    prompt = f"只回复这串标记：{token}"
    as_string = await _post(cfg, _base_spec(cfg, prompt=prompt, max_tokens=32))
    as_array = await _post(
        cfg,
        _base_spec(cfg, prompt="", max_tokens=32, body={"messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}]}),
    )
    if as_string.status is None or as_array.status is None:
        return CheckResult("MSG-07", NOT_TESTED, "请求未完成", f"字符串：{as_string.error or 'ok'}；数组：{as_array.error or 'ok'}")
    ok_string = as_string.ok and token in _content_text(as_string.json_body)
    ok_array = as_array.ok and token in _content_text(as_array.json_body)
    return CheckResult(
        "MSG-07",
        PASS if (ok_string and ok_array) else FAIL,
        f"字符串形式{'正常' if ok_string else '异常'}，数组形式{'正常' if ok_array else '异常'}",
        f"HTTP {as_string.status}/{as_array.status}",
    )


async def check_msg_special_chars(cfg: SuiteConfig) -> CheckResult:
    """MSG-08：中文、引号、反斜杠、Emoji、代码块等特殊文本无损。"""
    token = _token("SP")
    tricky = f'中文标记{token} 「引号」 "double" \\反斜杠\\ 🙂 代码：`print("ok")`'
    outcome = await _call(cfg, _base_spec(cfg, prompt=f"原样输出下面这一行，不要改动任何字符：\n{tricky}", max_tokens=80))
    if outcome.error_code and not outcome.text:
        return CheckResult("MSG-08", NOT_TESTED, "未能取得响应", _brief(outcome.error_message or outcome.error_code))
    text = outcome.text or ""
    checks = {
        "中文": token in text,
        "引号": "「引号」" in text,
        "反斜杠": "\\反斜杠\\" in text,
        "Emoji": "🙂" in text,
        "代码块": 'print("ok")' in text,
    }
    passed = all(checks.values())
    failed = [name for name, ok in checks.items() if not ok]
    return CheckResult(
        "MSG-08",
        PASS if passed else FAIL,
        "特殊字符均完整保留" if passed else f"以下内容被改动或丢失：{'、'.join(failed)}",
        f"响应片段：{_brief(text)}",
    )


# ---------------------------------------------------------------------------
# 2.4 长上下文与内容完整性
# ---------------------------------------------------------------------------
def _long_context(fill: str, markers: list[str], size: int = 1200) -> str:
    chunk = (fill * 40)[:size]
    return f"{markers[0]}\n{chunk}\n{markers[1]}\n{chunk}\n{markers[2]}\n{chunk}"


async def check_ctx_long_system(cfg: SuiteConfig) -> CheckResult:
    """CTX-01：长 system 的首/中/尾标记都能被提取。"""
    marks = [_token("S1"), _token("S2"), _token("S3")]
    system = _long_context("这是系统提示中的填充内容，用于占据上下文长度。", marks)
    prompt = "请依次输出 system 中出现的三个标记，用空格分隔，不要输出其他内容。"
    outcome = await _call(cfg, _base_spec(cfg, system=system, prompt=prompt, max_tokens=60))
    if outcome.error_code and not outcome.text:
        return CheckResult("CTX-01", NOT_TESTED, "未能取得响应", _brief(outcome.error_message or outcome.error_code))
    text = outcome.text or ""
    found = [m for m in marks if m in text]
    return CheckResult(
        "CTX-01",
        PASS if len(found) == 3 else FAIL,
        f"三个位置标记命中 {len(found)}/3",
        f"缺失：{[m for m in marks if m not in text]}；响应片段：{_brief(text)}",
    )


async def check_ctx_long_user(cfg: SuiteConfig) -> CheckResult:
    """CTX-02：长用户消息的首/中/尾标记都能被提取。"""
    marks = [_token("U1"), _token("U2"), _token("U3")]
    prompt = _long_context("这是用户消息中的填充内容，用于占据上下文长度。", marks) + "\n请依次输出上面的三个标记，用空格分隔。"
    outcome = await _call(cfg, _base_spec(cfg, prompt=prompt, max_tokens=60))
    if outcome.error_code and not outcome.text:
        return CheckResult("CTX-02", NOT_TESTED, "未能取得响应", _brief(outcome.error_message or outcome.error_code))
    text = outcome.text or ""
    found = [m for m in marks if m in text]
    return CheckResult(
        "CTX-02",
        PASS if len(found) == 3 else FAIL,
        f"三个位置标记命中 {len(found)}/3",
        f"缺失：{[m for m in marks if m not in text]}；响应片段：{_brief(text)}",
    )


async def check_ctx_multi_turn(cfg: SuiteConfig) -> CheckResult:
    """CTX-03：多轮长历史中的早期标记仍可被引用。"""
    early, middle, recent = _token("E"), _token("M"), _token("R")
    messages = [
        {"role": "user", "content": f"早期信息：{early}。" + "填充内容。" * 120},
        {"role": "assistant", "content": "已记录。"},
        {"role": "user", "content": f"中期信息：{middle}。" + "填充内容。" * 120},
        {"role": "assistant", "content": "已记录。"},
        {"role": "user", "content": f"最近信息：{recent}。请依次输出早期、中期、最近三个信息。"},
    ]
    result = await _post(cfg, _base_spec(cfg, prompt="", max_tokens=80, body=_messages_body(cfg.adapter, messages)))
    if result.status is None:
        return CheckResult("CTX-03", NOT_TESTED, "请求未完成", result.error)
    if not result.ok:
        return CheckResult("CTX-03", FAIL, f"长历史请求被拒绝（HTTP {result.status}）", _brief(result.error_message() or result.text))
    text = _content_text(result.json_body)
    found = [t for t in (early, middle, recent) if t in text]
    return CheckResult(
        "CTX-03",
        PASS if len(found) == 3 else FAIL,
        f"历史标记命中 {len(found)}/3",
        f"缺失：{[t for t in (early, middle, recent) if t not in text]}；响应片段：{_brief(text)}",
    )


def _prompt_tokens(payload: dict[str, Any]) -> int | None:
    usage = _usage(payload)
    for key in ("prompt_tokens", "input_tokens", "promptTokenCount"):
        if usage.get(key) is not None:
            try:
                return int(usage[key])
            except (TypeError, ValueError):
                return None
    return None


def _context_prompt(limit: int, ratio: float) -> str:
    """按声明上限构造长上下文；中文按 2 字符/token 保守估算，宁小勿超。"""
    chars = max(200, int(limit * 2 * ratio))
    unit = "这是一段用于上下文上限测试的占位文本，只用于占满声明长度。"
    body = (unit * (chars // len(unit) + 1))[:chars]
    return body + "\n\n请只回复：OK"


async def check_ctx_near_limit(cfg: SuiteConfig) -> CheckResult:
    """CTX-04：接近声明上限的请求应被接受且能正常回答。"""
    limit = _int_param("context_limit_tokens")
    if not limit:
        return CheckResult("CTX-04", NOT_TESTED, "未配置 context_limit_tokens，无法构造近上限请求", "标准未定义")
    last = ""
    for ratio in (0.9, 0.75):
        result = await _post(
            cfg,
            _base_spec(cfg, prompt=_context_prompt(limit, ratio), max_tokens=32, temperature=0),
        )
        if result.status is None:
            return CheckResult("CTX-04", NOT_TESTED, "近上限请求未完成", result.error)
        if 500 <= result.status < 600:
            return CheckResult("CTX-04", BLOCKED, f"上游返回 HTTP {result.status}，无法判定", _brief(result.text), "upstream_unavailable")
        if 400 <= result.status < 500:
            last = _brief(result.error_message() or result.text)
            continue  # 估算可能偏高，退一档再试
        text = _content_text(result.json_body)
        tokens = _prompt_tokens(result.json_body)
        if tokens is not None and tokens > limit:
            last = f"估算请求达到 {tokens} tokens，超过声明上限"
            continue
        if not text.strip():
            return CheckResult("CTX-04", FAIL, "近上限请求返回空回答", f"prompt_tokens={tokens}")
        return CheckResult(
            "CTX-04",
            PASS,
            f"近上限请求被接受并正常回答（prompt_tokens={tokens or '未提供'}，声明上限={limit}）",
            f"响应片段：{_brief(text)}",
        )
    return CheckResult("CTX-04", FAIL, f"接近声明上限（{limit} tokens）的请求被拒绝", last)


async def check_ctx_over_limit(cfg: SuiteConfig) -> CheckResult:
    """CTX-05：超过声明上限的请求必须明确报错，不得静默截断后返回成功。"""
    limit = _int_param("context_limit_tokens")
    if not limit:
        return CheckResult("CTX-05", NOT_TESTED, "未配置 context_limit_tokens，无法构造超限请求", "标准未定义")
    last = ""
    for ratio in (1.25, 1.6):
        result = await _post(
            cfg,
            _base_spec(cfg, prompt=_context_prompt(limit, ratio), max_tokens=32, temperature=0),
        )
        if result.status is None:
            return CheckResult("CTX-05", NOT_TESTED, "超限请求未完成", result.error)
        if 500 <= result.status < 600:
            return CheckResult("CTX-05", BLOCKED, f"上游返回 HTTP {result.status}，无法判定", _brief(result.text), "upstream_unavailable")
        body = _brief(result.error_message() or result.text)
        if 400 <= result.status < 500:
            if _mentions(body, ("context", "token", "length", "maximum", "too long", "超出", "过长", "长度")):
                return CheckResult("CTX-05", PASS, f"超限请求被明确拒绝（HTTP {result.status}）", body)
            return CheckResult("CTX-05", PENDING, f"HTTP {result.status} 但错误未指向上下文长度（归因不明）", body)
        text = _content_text(result.json_body)
        tokens = _prompt_tokens(result.json_body)
        if tokens is not None and tokens > limit:
            return CheckResult("CTX-05", FAIL, f"超限请求被接受（prompt_tokens={tokens} > {limit}）", f"响应片段：{_brief(text)}")
        last = f"HTTP {result.status}，prompt_tokens={tokens or '未提供'}"
    return CheckResult("CTX-05", FAIL, "无法确认超限处理：放大到 1.6 倍仍被接受", last)


# ---------------------------------------------------------------------------
# 2.5 请求参数
# ---------------------------------------------------------------------------
async def check_param_max_tokens(cfg: SuiteConfig) -> CheckResult:
    """PARAM-01：输出上限生效且到达上限时正确标记结束原因。"""
    outcome = await _call(
        cfg,
        _base_spec(cfg, prompt="请连续输出 500 个“测试”，不要省略。", max_tokens=24, temperature=0),
    )
    if outcome.error_code and not outcome.text:
        return CheckResult("PARAM-01", NOT_TESTED, "未能取得响应", _brief(outcome.error_message or outcome.error_code))
    completion = _usage(outcome.usage).get("completion_tokens")
    finish = (outcome.finish_reason or "").lower()
    limited = finish in {"length", "max_tokens", "length_exceeded"}
    within = completion is None or int(completion) <= 40
    ok = limited and within
    return CheckResult(
        "PARAM-01",
        PASS if ok else FAIL,
        f"结束原因={finish or '空'}，输出 token={completion}",
        "达到上限时应返回 length/max_tokens 类结束原因" if not ok else "上限生效且结束原因正确",
    )


async def check_param_temperature(cfg: SuiteConfig) -> CheckResult:
    """PARAM-02：合法采样值可接受，越界值明确报错。"""
    if cfg.adapter not in OPENAI_LIKE | {ANTHROPIC}:
        return CheckResult("PARAM-02", BLOCKED, "当前协议不适用温度越界检查", "该检查针对 OpenAI / Anthropic 的 temperature 取值", blocker_reason="executor_not_implemented_for_adapter")
    legal = await _post(cfg, _base_spec(cfg, prompt="只回复 OK", max_tokens=16, temperature=0))
    illegal = await _post(cfg, _base_spec(cfg, prompt="只回复 OK", max_tokens=16, temperature=2.5))
    if legal.status is None or illegal.status is None:
        return CheckResult(
            "PARAM-02",
            BLOCKED,
            "请求未完成（超时/连接失败）",
            f"合法值：{legal.error or 'ok'}；越界值：{illegal.error or 'ok'}",
            blocker_reason="upstream_unavailable",
        )
    # 第一步：合法值必须被接受。5xx 是上游故障（无法判定），4xx 才是"拒绝合法值"。
    if not legal.ok:
        if (legal.status or 0) >= 500:
            return CheckResult(
                "PARAM-02",
                BLOCKED,
                f"合法 temperature=0 时上游 HTTP {legal.status}（服务端故障，无法判定）",
                _brief(legal.error_message() or legal.text),
                blocker_reason="upstream_unavailable",
            )
        return CheckResult(
            "PARAM-02",
            FAIL,
            f"合法 temperature=0 被拒绝（HTTP {legal.status}）",
            _brief(legal.error_message() or legal.text),
        )
    # 第二步：越界值必须"明确拒绝"。Q10 三态：指向 temperature 的 4xx → pass；
    # 4xx 但归因不明 → pending；5xx → blocked；2xx（静默接受）→ fail。
    status, actual, blocker = capability_verdict(
        illegal, ("temperature", "range", "between", "must be", "out of")
    )
    if status == NOT_TESTED:
        return CheckResult(
            "PARAM-02",
            FAIL,
            f"合法值 HTTP {legal.status}；越界值 HTTP {illegal.status}（被静默接受）",
            "越界 temperature=2.5 未报错，原文要求明确报错",
        )
    return CheckResult(
        "PARAM-02",
        status,
        f"合法值 HTTP {legal.status}；越界值：{actual}",
        _brief(illegal.error_message() or illegal.text),
        blocker,
    )


async def check_param_stop(cfg: SuiteConfig) -> CheckResult:
    """PARAM-03：停止序列生效（OpenAI 用 stop，Anthropic 用 stop_sequences）。"""
    token = _token("STOP")
    body = {"stop_sequences": ["###"]} if cfg.adapter == ANTHROPIC else {"stop": ["###"]}
    result = await _post(
        cfg,
        _base_spec(
            cfg,
            prompt=f"依次输出：AA、###、{token}。不要省略任何部分。",
            max_tokens=120 if cfg.adapter == ANTHROPIC else 60,
            temperature=0,
            body=body,
        ),
    )
    if result.status is None:
        return CheckResult("PARAM-03", NOT_TESTED, "请求未完成", result.error)
    if 400 <= result.status < 500:
        status, actual, blocker = capability_verdict(result, ("stop", "sequence", "parameter"))
        return CheckResult("PARAM-03", status, actual, _brief(result.error_message() or result.text), blocker)
    if not result.ok:
        return CheckResult("PARAM-03", FAIL, f"停止序列被拒绝（HTTP {result.status}）", _brief(result.error_message() or result.text))
    text = _content_text(result.json_body)
    stopped = token not in text
    return CheckResult(
        "PARAM-03",
        PASS if stopped else FAIL,
        "停止序列之后的标记未输出" if stopped else "停止序列未生效，后续标记仍被输出",
        f"响应片段：{_brief(text)}",
    )


async def check_stream_switch(cfg: SuiteConfig) -> CheckResult:
    """PARAM-04：stream 开关被真正遵循。"""
    token = _token("SW")
    plain = await _call(cfg, _base_spec(cfg, prompt=f"只回复 {token}", max_tokens=24))
    streamed = await _call(cfg, _base_spec(cfg, prompt=f"只回复 {token}", max_tokens=24, stream=True))
    plain_ok = plain.ok and bool(plain.text)
    stream_ok = streamed.ok and streamed.chunk_count > 0 and bool(streamed.text)
    if not plain_ok and not stream_ok:
        return CheckResult(
            "PARAM-04",
            NOT_TESTED,
            "两种模式均未取得有效响应",
            f"非流式：{_brief(plain.error_message or plain.error_code or '空响应')}；流式：{_brief(streamed.error_message or streamed.error_code or '空响应')}",
        )
    return CheckResult(
        "PARAM-04",
        PASS if (plain_ok and stream_ok) else FAIL,
        f"非流式{'正常' if plain_ok else '异常'}，流式{'正常' if stream_ok else '异常'}",
        f"非流式 HTTP {plain.http_status} 文本 {len(plain.text)} 字；流式 HTTP {streamed.http_status} 事件块 {streamed.chunk_count}",
    )


async def check_param_stream_usage(cfg: SuiteConfig) -> CheckResult:
    """PARAM-05：流式用量可取得。"""
    token = _token("SU")
    streamed = await _call(cfg, _base_spec(cfg, prompt=f"只回复 {token}", max_tokens=24, stream=True, stream_usage=True))
    if not streamed.ok or streamed.chunk_count == 0:
        return CheckResult("PARAM-05", NOT_TESTED, "流式请求未成功", _brief(streamed.error_message or "未收到事件"))
    usage = streamed.usage or {}
    completion = usage.get("completion_tokens") or usage.get("output_tokens")
    ok = bool(usage) and completion not in (None, 0)
    return CheckResult(
        "PARAM-05",
        PASS if ok else FAIL,
        f"流式用量{'已返回' if ok else '缺失或为零'}（{completion}）",
        f"usage 字段：{_brief(usage)}",
    )


async def check_param_unknown_field(cfg: SuiteConfig) -> CheckResult:
    """PARAM-07：未知字段不得引发 5xx 或破坏模型路由。"""
    marker = _token("UNK")
    result = await _post(
        cfg,
        _base_spec(cfg, prompt="只回复 OK", max_tokens=16, temperature=0, body={"x_unknown_field_probe": marker}),
    )
    if result.status is None:
        return CheckResult("PARAM-07", NOT_TESTED, "请求未完成", result.error)
    if result.status >= 500:
        return CheckResult("PARAM-07", FAIL, f"未知字段导致服务端错误（HTTP {result.status}）", _brief(result.text))
    accepted = result.ok
    rejected = 400 <= result.status < 500
    return CheckResult(
        "PARAM-07",
        PASS if (accepted or rejected) else FAIL,
        f"未知字段被{'接受（忽略）' if accepted else '明确拒绝'}，HTTP {result.status}",
        "未知字段不应导致 5xx 或错误路由" if (accepted or rejected) else "行为异常",
    )


# ---------------------------------------------------------------------------
# 2.6 工具调用
# ---------------------------------------------------------------------------
def _openai_tools(with_time: bool = False) -> list[dict[str, Any]]:
    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "查询指定城市的天气",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string", "description": "城市名"},
                        "unit": {"type": "string", "enum": ["c", "f"]},
                    },
                    "required": ["city"],
                },
            },
        }
    ]
    if with_time:
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": "get_time",
                    "description": "查询指定城市的当前时间",
                    "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]},
                },
            }
        )
    return tools


def _anthropic_tools(with_time: bool = False) -> list[dict[str, Any]]:
    """同一组工具定义的 Anthropic Messages 形态（input_schema 而非 parameters）。"""
    tools = [
        {
            "name": "get_weather",
            "description": "查询指定城市的天气",
            "input_schema": {
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "城市名"},
                    "unit": {"type": "string", "enum": ["c", "f"]},
                },
                "required": ["city"],
            },
        }
    ]
    if with_time:
        tools.append(
            {
                "name": "get_time",
                "description": "查询指定城市的当前时间",
                "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]},
            }
        )
    return tools


def _tool_choice_value(cfg: SuiteConfig, choice: str) -> Any:
    """把统一写法映射到两种协议：auto / required / none。"""
    if cfg.adapter == ANTHROPIC:
        return {"auto": {"type": "auto"}, "required": {"type": "any"}, "none": {"type": "none"}}[choice]
    return {"auto": "auto", "required": "required", "none": "none"}[choice]


def _tool_body(
    cfg: SuiteConfig,
    choice: str | None = "auto",
    *,
    with_time: bool = False,
    messages: list[dict[str, Any]] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"tools": _anthropic_tools(with_time) if cfg.adapter == ANTHROPIC else _openai_tools(with_time)}
    if choice is not None:
        body["tool_choice"] = _tool_choice_value(cfg, choice)
    if messages is not None:
        body["messages"] = messages
    if extra:
        body.update(extra)
    return body


def _tool_name(call: dict[str, Any]) -> str:
    return str(call.get("name") or (call.get("function") or {}).get("name") or "")


def _tool_args(call: dict[str, Any]) -> Any:
    """返回解析后的参数对象；无法解析时返回 None。两种协议的参数位置不同。"""
    if "input" in call:
        value = call.get("input")
        return value if isinstance(value, dict) else None
    raw = (call.get("function") or {}).get("arguments")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw or "{}")
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _call_id(call: dict[str, Any]) -> str:
    return str(call.get("id") or "")


def _weather_problems(call: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    name = _tool_name(call)
    if name != "get_weather":
        problems.append(f"工具名 {name or '(空)'} 不在声明的 get_weather 内")
    args = _tool_args(call)
    if not isinstance(args, dict) or not args:
        problems.append("参数不可解析或为空")
        return problems
    city = args.get("city")
    if not isinstance(city, str) or not city.strip():
        problems.append("缺少必填参数 city")
    if "unit" in args and args["unit"] not in ("c", "f"):
        problems.append(f"unit={args['unit']!r} 不在枚举 [c, f] 内")
    return problems


def _call_summary(call: dict[str, Any]) -> str:
    return f"{_tool_name(call)}({json.dumps(_tool_args(call) or {}, ensure_ascii=False)}) id={_call_id(call)[:16]}"


async def check_tool_basic(cfg: SuiteConfig) -> CheckResult:
    """TOOL-01：工具定义被正确解析并产生**满足声明约束**的调用（双协议）。"""
    result = await _post(
        cfg,
        _base_spec(
            cfg,
            prompt="北京现在天气如何？请调用工具查询。",
            max_tokens=256 if cfg.adapter == ANTHROPIC else 120,
            temperature=0,
            body=_tool_body(cfg, "auto"),
        ),
    )
    if result.status is None:
        return CheckResult("TOOL-01", NOT_TESTED, "请求未完成", result.error)
    if 400 <= result.status < 500:
        status, actual, blocker = capability_verdict(result, ("tool", "工具", "function"))
        return CheckResult("TOOL-01", status, actual, _brief(result.error_message() or result.text), blocker)
    if not result.ok:
        return CheckResult("TOOL-01", FAIL, f"请求异常（HTTP {result.status}）", _brief(result.text))
    calls = _tool_calls(result.json_body)
    if not calls:
        return CheckResult("TOOL-01", FAIL, "未返回工具调用", f"响应片段：{_brief(_content_text(result.json_body))}")
    problems = _weather_problems(calls[0])
    actual = (
        f"返回 {len(calls)} 个调用，参数{'符合声明' if not problems else '不符合声明'}"
        + ("：" + "；".join(problems) if problems else "")
    )
    return CheckResult("TOOL-01", PASS if not problems else FAIL, actual, f"调用摘要：{_brief(_call_summary(calls[0]))}")


async def check_tool_auto(cfg: SuiteConfig) -> CheckResult:
    """TOOL-02：不给 tool_choice 时，模型应按任务自动选中工具；允许不选，但选了必须选对。"""
    result = await _post(
        cfg,
        _base_spec(
            cfg,
            prompt="请使用工具查询北京现在的天气。",
            max_tokens=256 if cfg.adapter == ANTHROPIC else 120,
            temperature=0,
            body=_tool_body(cfg, None),
        ),
    )
    if result.status is None:
        return CheckResult("TOOL-02", NOT_TESTED, "请求未完成", result.error)
    if 400 <= result.status < 500:
        status, actual, blocker = capability_verdict(result, ("tool", "工具", "function", "choice"))
        return CheckResult("TOOL-02", status, actual, _brief(result.error_message() or result.text), blocker)
    if not result.ok:
        return CheckResult("TOOL-02", FAIL, f"请求异常（HTTP {result.status}）", _brief(result.text))
    calls = _tool_calls(result.json_body)
    if not calls:
        return CheckResult(
            "TOOL-02",
            FAIL,
            "任务明确要求查天气，但未自动选择任何工具",
            f"响应片段：{_brief(_content_text(result.json_body))}",
        )
    problems = _weather_problems(calls[0])
    return CheckResult(
        "TOOL-02",
        PASS if not problems else FAIL,
        f"自动选择了 {_tool_name(calls[0]) or '(空)'}，参数{'有效' if not problems else '无效'}"
        + ("：" + "；".join(problems) if problems else ""),
        f"调用摘要：{_brief(_call_summary(calls[0]))}",
    )


async def check_tool_required(cfg: SuiteConfig) -> CheckResult:
    """TOOL-03：tool_choice 强制调用生效。"""
    result = await _post(
        cfg,
        _base_spec(
            cfg,
            prompt="介绍一下你自己。",
            max_tokens=256 if cfg.adapter == ANTHROPIC else 120,
            temperature=0,
            body=_tool_body(cfg, "required"),
        ),
    )
    if result.status is None:
        return CheckResult("TOOL-03", NOT_TESTED, "请求未完成", result.error)
    if 400 <= result.status < 500:
        status, actual, blocker = capability_verdict(result, ("tool", "工具", "choice"))
        return CheckResult("TOOL-03", status, actual, _brief(result.error_message() or result.text), blocker)
    if not result.ok:
        return CheckResult("TOOL-03", FAIL, f"请求异常（HTTP {result.status}）", _brief(result.text))
    calls = _tool_calls(result.json_body)
    return CheckResult("TOOL-03", PASS if calls else FAIL, f"强制调用{'已产生' if calls else '未产生'}工具调用", f"工具调用数：{len(calls)}")


async def check_tool_none(cfg: SuiteConfig) -> CheckResult:
    """TOOL-04：禁止调用时不返回工具调用。"""
    result = await _post(
        cfg,
        _base_spec(
            cfg,
            prompt="北京现在天气如何？",
            max_tokens=256 if cfg.adapter == ANTHROPIC else 120,
            temperature=0,
            body=_tool_body(cfg, "none"),
        ),
    )
    if result.status is None:
        return CheckResult("TOOL-04", NOT_TESTED, "请求未完成", result.error)
    if 400 <= result.status < 500:
        status, actual, blocker = capability_verdict(result, ("tool", "工具", "choice"))
        return CheckResult("TOOL-04", status, actual, _brief(result.error_message() or result.text), blocker)
    if not result.ok:
        return CheckResult("TOOL-04", FAIL, f"请求异常（HTTP {result.status}）", _brief(result.text))
    calls = _tool_calls(result.json_body)
    return CheckResult("TOOL-04", PASS if not calls else FAIL, f"禁用后{'未' if not calls else '仍然'}返回工具调用", f"工具调用数：{len(calls)}")


def _roundtrip_messages(cfg: SuiteConfig, prompt: str, call: dict[str, Any]) -> list[dict[str, Any]]:
    call_id = _call_id(call)
    name = _tool_name(call) or "get_weather"
    args = _tool_args(call) or {"city": "北京"}
    result_payload = json.dumps({"temperature": 21, "unit": "c"}, ensure_ascii=False)
    if cfg.adapter == ANTHROPIC:
        return [
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": [{"type": "tool_use", "id": call_id, "name": name, "input": args}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": call_id, "content": result_payload}]},
        ]
    return [
        {"role": "user", "content": prompt},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(args, ensure_ascii=False)}}],
        },
        {"role": "tool", "tool_call_id": call_id, "content": result_payload},
    ]


async def check_tool_roundtrip(cfg: SuiteConfig) -> CheckResult:
    """TOOL-05：工具结果回传后能继续回答，调用 ID 关联正确。"""
    prompt = "北京现在天气如何？请调用工具查询。"
    first = await _post(
        cfg,
        _base_spec(
            cfg,
            prompt=prompt,
            max_tokens=256 if cfg.adapter == ANTHROPIC else 120,
            temperature=0,
            body=_tool_body(cfg, "auto"),
        ),
    )
    if first.status is None:
        return CheckResult("TOOL-05", NOT_TESTED, "请求未完成", first.error)
    calls = _tool_calls(first.json_body)
    if not first.ok or not calls:
        return CheckResult("TOOL-05", NOT_APPLICABLE, "首轮未产生工具调用，无法验证闭环", f"HTTP {first.status}；调用数 {len(calls)}")
    if not _call_id(calls[0]):
        return CheckResult("TOOL-05", FAIL, "返回的工具调用缺少 id，无法关联结果", _brief(_call_summary(calls[0])))
    messages = _roundtrip_messages(cfg, prompt, calls[0])
    second = await _post(
        cfg,
        _base_spec(
            cfg,
            prompt="",
            max_tokens=256 if cfg.adapter == ANTHROPIC else 120,
            temperature=0,
            body=_tool_body(cfg, None, messages=messages),
        ),
    )
    if second.status is None:
        return CheckResult("TOOL-05", NOT_TESTED, "回传请求未完成", second.error)
    if not second.ok:
        return CheckResult("TOOL-05", FAIL, f"工具结果回传被拒绝（HTTP {second.status}）", _brief(second.error_message() or second.text))
    text = _content_text(second.json_body)
    used_result = "21" in text
    ok = bool(text.strip()) and used_result
    actual = (
        f"回传后{'继续生成了回答' if text.strip() else '未生成回答'}"
        f"，{'已引用' if used_result else '未引用'}回传的工具结果（21）"
    )
    return CheckResult("TOOL-05", PASS if ok else FAIL, actual, f"调用 ID {_call_id(calls[0])[:12]}…；响应片段：{_brief(text)}")


async def check_tool_multi(cfg: SuiteConfig) -> CheckResult:
    """TOOL-06：同轮多个工具调用的名称/参数/ID 独立完整。"""
    result = await _post(
        cfg,
        _base_spec(
            cfg,
            prompt="请同时查询北京天气和北京当前时间，两个工具都要调用。",
            max_tokens=384 if cfg.adapter == ANTHROPIC else 160,
            temperature=0,
            body=_tool_body(cfg, "auto", with_time=True),
        ),
    )
    if result.status is None:
        return CheckResult("TOOL-06", NOT_TESTED, "请求未完成", result.error)
    if 400 <= result.status < 500:
        status, actual, blocker = capability_verdict(result, ("tool", "工具", "parallel"))
        return CheckResult("TOOL-06", status, actual, _brief(result.error_message() or result.text), blocker)
    if not result.ok:
        return CheckResult("TOOL-06", FAIL, f"请求异常（HTTP {result.status}）", _brief(result.text))
    calls = _tool_calls(result.json_body)
    ids = [_call_id(c) for c in calls]
    names = [_tool_name(c) for c in calls]
    ok = len(calls) >= 2 and all(ids) and len(set(ids)) == len(ids) and len(set(names)) >= 2
    return CheckResult(
        "TOOL-06",
        PASS if ok else FAIL,
        f"返回 {len(calls)} 个调用，名称 {names}，ID 唯一={len(set(ids)) == len(ids)}",
        "多工具调用的 ID 与名称应各自独立" if not ok else "多工具调用彼此独立",
    )


async def _stream_tool_calls(cfg: SuiteConfig, spec: CallSpec) -> tuple[RawResult, list[dict[str, Any]]]:
    """读取一次工具调用的 SSE 流，按协议拼接分片参数。"""
    allowed, reason = take_request()
    if not allowed:
        return RawResult(error=reason), []
    try:
        prepared = _adapter(cfg).build(spec)
        validate_url(prepared.url, resolve=True)
    except Exception as exc:  # noqa: BLE001
        return RawResult(error=f"无法构造或校验请求：{getattr(exc, 'message', exc)}"), []

    calls: dict[int, dict[str, Any]] = {}
    timeout = httpx.Timeout(min(cfg.total_timeout, 40), connect=cfg.connect_timeout)
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            async with client.stream("POST", prepared.url, headers=prepared.headers, json=prepared.json_body) as response:
                if response.status_code >= 400:
                    text = (await response.aread()).decode("utf-8", "replace")[:1000]
                    return RawResult(status=response.status_code, text=text), []
                async for line in response.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if not data or data == "[DONE]":
                        continue
                    try:
                        event = json.loads(data)
                    except ValueError:
                        continue
                    if cfg.adapter == ANTHROPIC:
                        kind = event.get("type")
                        if kind == "content_block_start" and (event.get("content_block") or {}).get("type") == "tool_use":
                            block = event.get("content_block") or {}
                            calls[event.get("index", 0)] = {"id": block.get("id", ""), "name": block.get("name", ""), "args": ""}
                        elif kind == "content_block_delta" and (event.get("delta") or {}).get("type") == "input_json_delta":
                            slot = calls.setdefault(event.get("index", 0), {"id": "", "name": "", "args": ""})
                            slot["args"] += (event.get("delta") or {}).get("partial_json", "")
                    else:
                        for chunk in (event.get("choices") or [{}])[0].get("delta", {}).get("tool_calls") or []:
                            index = int(chunk.get("index", 0))
                            slot = calls.setdefault(index, {"id": "", "name": "", "args": ""})
                            slot["id"] += chunk.get("id") or ""
                            fn = chunk.get("function") or {}
                            slot["name"] += fn.get("name") or ""
                            slot["args"] += fn.get("arguments") or ""
    except Exception as exc:  # noqa: BLE001 - 网络异常即无证据
        return RawResult(error=_brief(exc)), []

    normalized: list[dict[str, Any]] = []
    for index in sorted(calls):
        slot = calls[index]
        try:
            args = json.loads(slot["args"] or "{}")
        except ValueError:
            args = slot["args"]
        normalized.append({"id": slot["id"], "name": slot["name"], "input": args})
    return RawResult(status=200, json_body={}), normalized


async def check_tool_stream_args(cfg: SuiteConfig) -> CheckResult:
    """TOOL-07：流式下工具参数分片必须能拼成完整 JSON，ID/名称不丢。"""
    prompt = "北京现在天气如何？请调用工具查询。"
    spec = _base_spec(
        cfg,
        prompt=prompt,
        max_tokens=256 if cfg.adapter == ANTHROPIC else 160,
        temperature=0,
        stream=True,
        body=_tool_body(cfg, "required"),
    )
    result, calls = await _stream_tool_calls(cfg, spec)
    if result.status is None:
        return CheckResult("TOOL-07", NOT_TESTED, "流式请求未完成", result.error)
    if 400 <= (result.status or 0) < 500:
        status, actual, blocker = capability_verdict(result, ("tool", "工具", "stream"))
        return CheckResult("TOOL-07", status, actual, _brief(result.text), blocker)
    if not (200 <= (result.status or 0) < 300):
        return CheckResult("TOOL-07", FAIL, f"流式请求异常（HTTP {result.status}）", _brief(result.text))
    if not calls:
        return CheckResult("TOOL-07", FAIL, "流式响应中未出现工具调用", "未收到 tool_use / tool_calls 事件")
    call = calls[0]
    args = _tool_args(call)
    ok = bool(_call_id(call)) and _tool_name(call) == "get_weather" and isinstance(args, dict) and bool(args.get("city"))
    return CheckResult(
        "TOOL-07",
        PASS if ok else FAIL,
        f"流式拼接出 {len(calls)} 个调用，参数{'完整' if isinstance(args, dict) else '仍是未解析字符串'}",
        f"调用摘要：{_brief(_call_summary(call))}",
    )


async def check_tool_bad_id(cfg: SuiteConfig) -> CheckResult:
    """TOOL-08：与原调用不匹配的工具结果必须报错。"""
    if cfg.adapter == ANTHROPIC:
        messages = [
            {"role": "user", "content": "北京天气如何？"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "call_valid_0001", "name": "get_weather", "input": {"city": "北京"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_mismatched_9999", "content": "{\"temperature\": 20}"}]},
        ]
    else:
        messages = [
            {"role": "user", "content": "北京天气如何？"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"id": "call_valid_0001", "type": "function", "function": {"name": "get_weather", "arguments": "{}"}}],
            },
            {"role": "tool", "tool_call_id": "call_mismatched_9999", "content": json.dumps({"temperature": 20})},
        ]
    result = await _post(
        cfg,
        _base_spec(cfg, prompt="", max_tokens=64, body=_tool_body(cfg, None, messages=messages)),
    )
    if result.status is None:
        return CheckResult("TOOL-08", NOT_TESTED, "请求未完成", result.error)
    rejected = 400 <= result.status < 500
    return CheckResult(
        "TOOL-08",
        PASS if rejected else FAIL,
        f"错配的工具结果{'被明确拒绝' if rejected else '被接受'}（HTTP {result.status}）",
        _brief(result.error_message() or result.text),
    )


# ---------------------------------------------------------------------------
# 2.7 图片
# ---------------------------------------------------------------------------
def _tiny_png_rgb(rgb: tuple[int, int, int] = (255, 0, 0)) -> str:
    """An 8x8 solid-colour PNG, base64-encoded (used for data-URL vision checks)."""
    width = height = 8
    pixel = bytes(rgb)
    raw = b"".join(b"\x00" + pixel * width for _ in range(height))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )
    return base64.b64encode(png).decode("ascii")


def _tiny_png_red() -> str:
    return _tiny_png_rgb((255, 0, 0))


async def check_media_data_url(cfg: SuiteConfig) -> CheckResult:
    """MEDIA-02：内嵌图片（data URL）可被读取，且结果与图片内容相符。"""
    if cfg.adapter not in OPENAI_LIKE:
        return CheckResult("MEDIA-02", BLOCKED, "当前协议的内嵌图片检查未实现", "仅 OpenAI Chat Completions 的 image_url 形式", blocker_reason="executor_not_implemented_for_adapter")
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "这张图片是什么颜色？只回答一个颜色词。"},
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{_tiny_png_red()}"}},
                ],
            }
        ]
    }
    result = await _post(cfg, _base_spec(cfg, prompt="", max_tokens=32, temperature=0, body=body))
    if result.status is None:
        return CheckResult("MEDIA-02", NOT_TESTED, "请求未完成", result.error)
    if not result.ok:
        return CheckResult("MEDIA-02", NOT_APPLICABLE, f"模型不接受图片输入（HTTP {result.status}）", _brief(result.error_message() or result.text))
    text = _content_text(result.json_body)
    ok = ("红" in text) or ("red" in text.lower())
    return CheckResult("MEDIA-02", PASS if ok else FAIL, f"图片颜色识别{'正确' if ok else '不正确'}", f"响应片段：{_brief(text)}")


async def check_media_invalid(cfg: SuiteConfig) -> CheckResult:
    """MEDIA-05：损坏的图片数据必须明确报错，不得静默返回纯文本答案。"""
    if cfg.adapter not in OPENAI_LIKE:
        return CheckResult("MEDIA-05", BLOCKED, "当前协议未实现无效图片检查", "仅 OpenAI Chat Completions", blocker_reason="executor_not_implemented_for_adapter")
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "这张图片是什么？"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,bm90LWFuLWltYWdl"}},
                ],
            }
        ]
    }
    result = await _post(cfg, _base_spec(cfg, prompt="", max_tokens=32, temperature=0, body=body))
    if result.status is None:
        return CheckResult("MEDIA-05", NOT_TESTED, "请求未完成", result.error)
    rejected = 400 <= result.status < 500
    return CheckResult(
        "MEDIA-05",
        PASS if rejected else FAIL,
        f"损坏图片被{'明确拒绝' if rejected else '静默接受'}（HTTP {result.status}）",
        _brief(result.error_message() or _content_text(result.json_body)),
    )


# ---------------------------------------------------------------------------
# 2.8 结构化输出
# ---------------------------------------------------------------------------
async def check_struct_json(cfg: SuiteConfig) -> CheckResult:
    """STRUCT-01：JSON 模式返回合法 JSON。"""
    if cfg.adapter not in OPENAI_LIKE:
        return CheckResult("STRUCT-01", BLOCKED, "当前协议的 JSON 模式检查未实现", "仅 OpenAI Chat Completions 的 response_format", blocker_reason="executor_not_implemented_for_adapter")
    result = await _post(
        cfg,
        _base_spec(
            cfg,
            prompt='只输出一个 JSON 对象，包含字段 ok（布尔）与 tag（字符串），不要输出其他内容。',
            max_tokens=120,
            temperature=0,
            body={"response_format": {"type": "json_object"}},
        ),
    )
    if result.status is None:
        return CheckResult("STRUCT-01", NOT_TESTED, "请求未完成", result.error)
    if not result.ok:
        return CheckResult("STRUCT-01", NOT_APPLICABLE, f"模型不支持 JSON 模式（HTTP {result.status}）", _brief(result.error_message() or result.text))
    text = _content_text(result.json_body).strip()
    try:
        parsed = json.loads(text[text.find("{") : text.rfind("}") + 1]) if "{" in text else None
        valid = isinstance(parsed, dict) and "ok" in parsed
    except ValueError:
        valid = False
    return CheckResult("STRUCT-01", PASS if valid else FAIL, f"返回内容{'是合法 JSON' if valid else '不是合法 JSON'}", f"响应片段：{_brief(text)}")


async def check_struct_schema(cfg: SuiteConfig) -> CheckResult:
    """STRUCT-02：严格 Schema 输出通过校验。"""
    if cfg.adapter not in OPENAI_LIKE:
        return CheckResult("STRUCT-02", BLOCKED, "当前协议的 Schema 检查未实现", "仅 OpenAI Chat Completions 的 json_schema", blocker_reason="executor_not_implemented_for_adapter")
    schema = {
        "type": "object",
        "properties": {"city": {"type": "string"}, "days": {"type": "integer"}},
        "required": ["city", "days"],
        "additionalProperties": False,
    }
    body = {
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "trip", "strict": True, "schema": schema},
        }
    }
    result = await _post(
        cfg,
        _base_spec(cfg, prompt="生成一个北京的 3 天行程摘要，只输出符合 schema 的 JSON。", max_tokens=160, temperature=0, body=body),
    )
    if result.status is None:
        return CheckResult("STRUCT-02", NOT_TESTED, "请求未完成", result.error)
    if not result.ok:
        return CheckResult("STRUCT-02", NOT_APPLICABLE, f"模型不支持严格 Schema（HTTP {result.status}）", _brief(result.error_message() or result.text))
    text = _content_text(result.json_body).strip()
    try:
        parsed = json.loads(text[text.find("{") : text.rfind("}") + 1]) if "{" in text else {}
    except ValueError:
        parsed = {}
    ok = (
        isinstance(parsed, dict)
        and isinstance(parsed.get("city"), str)
        and isinstance(parsed.get("days"), int)
        and set(parsed.keys()) <= {"city", "days"}
    )
    return CheckResult("STRUCT-02", PASS if ok else FAIL, f"输出{'通过' if ok else '未通过'} Schema 校验", f"解析结果：{_brief(parsed)}")


# ---------------------------------------------------------------------------
# 2.9 流式
# ---------------------------------------------------------------------------
async def check_sse_parse(cfg: SuiteConfig) -> CheckResult:
    """SSE-01：事件流**全程可解析，无畸形事件**。

    原文要求"全程可解析，无畸形事件"。过去只判 `ok`（=有正文、无错误码），
    而 `BaseStreamParser.feed()` 对无法解析的 `data:` 是 `except ValueError: continue`
    ——畸形事件被静默丢弃，所以这半句从未被判定（差距审计 F5）。
    """
    token = _token("SSE")
    outcome = await _call(cfg, _base_spec(cfg, prompt=f"用一句话说明下面标记的用途：{token}", max_tokens=64, stream=True))
    if outcome.chunk_count == 0:
        return CheckResult("SSE-01", NOT_TESTED, "未收到事件流", _brief(outcome.error_message or "上游未返回 text/event-stream"))
    parsed_ok = outcome.ok and not outcome.error_code and outcome.malformed_events == 0
    return CheckResult(
        "SSE-01",
        PASS if parsed_ok else FAIL,
        f"收到 {outcome.chunk_count} 个可解析事件块，畸形事件 {outcome.malformed_events} 个",
        f"HTTP {outcome.http_status}；错误码 {outcome.error_code or '无'}；拼接文本 {len(outcome.text)} 字",
    )


async def check_sse_concat(cfg: SuiteConfig) -> CheckResult:
    """SSE-02：增量拼接无乱码/丢字（中文、标点、换行）。"""
    token = _token("拼接")
    marker = f"标记{token}包含中文、标点，以及换行"
    outcome = await _call(cfg, _base_spec(cfg, prompt=f"请原样输出：{marker}", max_tokens=80, stream=True))
    if outcome.chunk_count == 0:
        return CheckResult("SSE-02", NOT_TESTED, "未收到事件流", _brief(outcome.error_message or "上游未返回 text/event-stream"))
    hit = token in outcome.text
    return CheckResult(
        "SSE-02",
        PASS if hit else FAIL,
        f"拼接结果{'完整包含' if hit else '未包含'}中文标记 {token}",
        f"事件块 {outcome.chunk_count}；拼接文本：{_brief(outcome.text)}",
    )


async def check_sse_finish_reason(cfg: SuiteConfig) -> CheckResult:
    """SSE-04：正常完成的结束原因符合协议语义。"""
    outcome = await _call(cfg, _base_spec(cfg, prompt="只回复 OK", max_tokens=24, stream=True))
    if not outcome.ok or outcome.chunk_count == 0:
        return CheckResult("SSE-04", NOT_TESTED, "流式请求未成功", _brief(outcome.error_message or "未收到事件"))
    finish = (outcome.finish_reason or "").lower()
    ok = finish in FINISH_REASON_WHITELIST
    return CheckResult("SSE-04", PASS if ok else FAIL, f"结束原因={finish or '空'}", "结束原因应为协议定义的可解析值" if not ok else "结束原因符合协议语义")


async def check_sse_usage(cfg: SuiteConfig) -> CheckResult:
    """SSE-05：已输出正文时用量字段可解析且不为零。"""
    token = _token("USG")
    outcome = await _call(cfg, _base_spec(cfg, prompt=f"只回复 {token}", max_tokens=32, stream=True, stream_usage=True))
    if not outcome.ok or outcome.chunk_count == 0:
        return CheckResult("SSE-05", NOT_TESTED, "流式请求未成功", _brief(outcome.error_message or "未收到事件"))
    usage = outcome.usage or {}
    completion = usage.get("completion_tokens") or usage.get("output_tokens")
    ok = bool(usage) and completion not in (None, 0) and bool(outcome.text)
    return CheckResult(
        "SSE-05",
        PASS if ok else FAIL,
        f"输出 {len(outcome.text)} 字，用量字段{'完整' if ok else '缺失或为零'}",
        f"usage：{_brief(usage)}",
    )


# ---------------------------------------------------------------------------
# 2.10 非法请求
# ---------------------------------------------------------------------------
async def check_invalid_json(cfg: SuiteConfig) -> CheckResult:
    """ERR-01：非法 JSON 必须被明确拒绝。"""
    try:
        prepared = _adapter(cfg).build(_base_spec(cfg, prompt="ping", max_tokens=16))
        validate_url(prepared.url, resolve=True)
    except Exception as exc:  # noqa: BLE001
        return CheckResult("ERR-01", NOT_TESTED, "无法构造请求", _brief(getattr(exc, "message", exc)))
    timeout = httpx.Timeout(min(cfg.total_timeout, 30), connect=cfg.connect_timeout)
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            response = await client.post(
                prepared.url,
                headers={**prepared.headers, "Content-Type": "application/json"},
                content=b'{"model": "x", "messages": [',
            )
    except Exception as exc:  # noqa: BLE001
        return CheckResult("ERR-01", NOT_TESTED, "请求未完成", _brief(str(exc)))
    rejected = 400 <= response.status_code < 500
    return CheckResult("ERR-01", PASS if rejected else FAIL, f"HTTP {response.status_code}（{'客户端错误' if rejected else '未按客户端错误拒绝'}）", f"响应片段：{_brief(response.text)}")


async def check_missing_field(cfg: SuiteConfig) -> CheckResult:
    """ERR-02：缺少 model 等必填字段必须明确报错。"""
    result = await _post(cfg, _base_spec(cfg, prompt="ping", max_tokens=16, body={"model": ""}))
    if result.status is None:
        return CheckResult("ERR-02", NOT_TESTED, "请求未完成", result.error)
    rejected = 400 <= result.status < 500
    return CheckResult("ERR-02", PASS if rejected else FAIL, f"HTTP {result.status}（{'明确拒绝' if rejected else '未拒绝缺少必填字段'}）", _brief(result.error_message() or result.text))


async def check_field_type_error(cfg: SuiteConfig) -> CheckResult:
    """ERR-03：字段类型错误必须明确拒绝，不得隐式转换。"""
    result = await _post(cfg, _base_spec(cfg, prompt="ping", max_tokens=16, body={"model": {"nested": "object"}}))
    if result.status is None:
        return CheckResult("ERR-03", NOT_TESTED, "请求未完成", result.error)
    # Q10 三态：明确拒绝→pass；拒绝但归因不明→pending；5xx/无响应→blocked。
    status, actual, blocker = capability_verdict(result, ("model", "type", "field", "invalid", "string", "object"))
    return CheckResult("ERR-03", status, f"类型错误：{actual}", _brief(result.error_message() or result.text), blocker)


async def check_invalid_role(cfg: SuiteConfig) -> CheckResult:
    """ERR-04：非法消息结构（角色）必须报错。"""
    body = _messages_body(cfg.adapter, [{"role": "systemx", "content": "非法角色测试"}])
    result = await _post(cfg, _base_spec(cfg, prompt="", max_tokens=16, body=body))
    if result.status is None:
        return CheckResult("ERR-04", NOT_TESTED, "请求未完成", result.error)
    status, actual, blocker = capability_verdict(result, ("role", "systemx", "message", "invalid"))
    return CheckResult("ERR-04", status, f"非法角色：{actual}", _brief(result.error_message() or result.text), blocker)


async def check_error_shape(cfg: SuiteConfig) -> CheckResult:
    """ERR-06：鉴权失败必须返回可识别的错误，不得包装成成功响应。"""
    spec = _base_spec(cfg, prompt="ping", max_tokens=16)
    spec.api_key = "invalid-key-for-error-shape-check"
    spec.api_secret = "invalid-secret"
    result = await _post(cfg, spec)
    if result.status is None:
        return CheckResult("ERR-06", NOT_TESTED, "请求未完成", result.error)
    rejected = result.status in (401, 403)
    identifiable = bool(result.error_code() or result.error_message()) or not result.ok
    ok = rejected and identifiable
    return CheckResult(
        "ERR-06",
        PASS if ok else FAIL,
        f"错误 Key 返回 HTTP {result.status}（{'可识别' if identifiable else '不可识别'}）",
        f"错误码：{_brief(result.error_code() or '无')}；响应片段：{_brief(result.text)}",
    )


# ---------------------------------------------------------------------------
# 3.4 缓存 / 4.5 能力 / 4.8 一致性
# ---------------------------------------------------------------------------
def _cache_probe_prompt(token: str, repeats: int = 60) -> str:
    filler = "缓存前缀填充内容，用于达到供应商的最小缓存长度要求。" * repeats
    return f"{filler}\n请只回复这串标记：{token}"


async def check_cache_hit(cfg: SuiteConfig) -> CheckResult:
    """CACHE-02：相同前缀重复请求应产生缓存读取。"""
    token = _token("CH")
    prompt = _cache_probe_prompt(token)
    first = await _post(cfg, _base_spec(cfg, prompt=prompt, max_tokens=24, temperature=0))
    if first.status is None:
        return CheckResult("CACHE-02", NOT_TESTED, "首次请求未完成", first.error)
    if not first.ok:
        return CheckResult("CACHE-02", NOT_TESTED, f"首次请求失败（HTTP {first.status}）", _brief(first.error_message() or first.text))
    second = await _post(cfg, _base_spec(cfg, prompt=prompt, max_tokens=24, temperature=0))
    if second.status is None or not second.ok:
        return CheckResult("CACHE-02", NOT_TESTED, "第二次请求未完成", second.error or f"HTTP {second.status}")
    cached = _cached_tokens(second.json_body)
    if cached is None:
        return CheckResult(
            "CACHE-02",
            NOT_APPLICABLE,
            "响应未提供缓存用量字段",
            "供应商未返回 cached_tokens / cache_read_input_tokens，无法判定命中；需供应商提供用量字段后复测",
        )
    ok = cached > 0
    return CheckResult(
        "CACHE-02",
        PASS if ok else FAIL,
        f"第二次请求缓存读取 {cached} tokens",
        "命中应出现与可复用前缀规模相符的读取量" if ok else "重复请求未命中缓存",
    )


async def check_cap_text(cfg: SuiteConfig) -> CheckResult:
    """CAP-01：基础指令与信息处理能力。"""
    token = _token("CAP")
    outcome = await _call(
        cfg,
        _base_spec(cfg, prompt=f"把下面内容原样放进尖括号中输出：【{token}】只输出结果。", max_tokens=32),
    )
    if outcome.error_code and not outcome.text:
        return CheckResult("CAP-01", NOT_TESTED, "未能取得响应", _brief(outcome.error_message or outcome.error_code))
    ok = f"【{token}】" in (outcome.text or "")
    return CheckResult("CAP-01", PASS if ok else FAIL, f"格式化指令{'被执行' if ok else '未被执行'}", f"响应片段：{_brief(outcome.text)}")


async def check_cap_multilingual(cfg: SuiteConfig) -> CheckResult:
    """CAP-02：中英文等价任务均可完成。"""
    zh = await _call(cfg, _base_spec(cfg, prompt="把 apple 翻译成中文，只输出中文词。", max_tokens=16))
    en = await _call(cfg, _base_spec(cfg, prompt="把“苹果”翻译成英文，只输出英文词。", max_tokens=16))
    if (zh.error_code and not zh.text) and (en.error_code and not en.text):
        return CheckResult("CAP-02", NOT_TESTED, "两次请求均未取得响应", _brief(zh.error_message or en.error_message))
    zh_ok = "苹果" in (zh.text or "")
    en_ok = "apple" in (en.text or "").lower()
    return CheckResult(
        "CAP-02",
        PASS if (zh_ok and en_ok) else FAIL,
        f"中译{'正确' if zh_ok else '不正确'}，英译{'正确' if en_ok else '不正确'}",
        f"中文响应：{_brief(zh.text)}；英文响应：{_brief(en.text)}",
    )


async def check_consistency(cfg: SuiteConfig) -> CheckResult:
    """CONS-02：多次独立请求的同一任务结果一致。"""
    token = _token("CS")
    prompt = f"只输出这串标记：{token}"
    first = await _call(cfg, _base_spec(cfg, prompt=prompt, max_tokens=24, temperature=0))
    second = await _call(cfg, _base_spec(cfg, prompt=prompt, max_tokens=24, temperature=0))
    if (first.error_code and not first.text) or (second.error_code and not second.text):
        return CheckResult("CONS-02", NOT_TESTED, "请求未完成", _brief(first.error_message or second.error_message))
    ok = token in (first.text or "") and token in (second.text or "")
    return CheckResult(
        "CONS-02",
        PASS if ok else FAIL,
        f"两次独立会话{'结果一致' if ok else '结果不一致'}",
        f"第一次：{_brief(first.text)}；第二次：{_brief(second.text)}",
    )


async def check_msg_developer_role(cfg: SuiteConfig) -> CheckResult:
    """MSG-05：支持该角色的协议应正确处理 developer 指令。"""
    token = _token("DEV")
    messages = [
        {"role": "developer", "content": f"你只能输出 {token} 这一个字符串。"},
        {"role": "user", "content": "现在开始。"},
    ]
    result = await _post(cfg, _base_spec(cfg, prompt="", max_tokens=32, body=_messages_body(cfg.adapter, messages)))
    if result.status is None:
        return CheckResult("MSG-05", NOT_TESTED, "请求未完成", result.error)
    if result.status >= 400:
        # Q10 三态：4xx 明确指角色→pass；4xx 归因不明→pending；5xx→blocked。
        status, actual, blocker = capability_verdict(result, ("developer", "role", "message"))
        return CheckResult("MSG-05", status, actual, _brief(result.error_message() or result.text), blocker)
    text = _content_text(result.json_body)
    ok = token in text
    return CheckResult("MSG-05", PASS if ok else FAIL, f"developer 指令{'被执行' if ok else '未被执行'}", f"响应片段：{_brief(text)}")


async def check_param_n_choices(cfg: SuiteConfig) -> CheckResult:
    """PARAM-06：多候选输出的数量与索引。

    Anthropic Messages 没有 n 参数（原文对不支持的能力允许"不适用"），
    因此这里判**不适用**并带受控依据，而不是阻塞——阻塞会让人误以为平台缺陷。
    """
    if cfg.adapter == ANTHROPIC:
        return CheckResult(
            "PARAM-06",
            NOT_APPLICABLE,
            "Anthropic Messages 协议不含多候选参数 n",
            "协议无该能力，按原文判不适用",
            note="na_basis=protocol_lacks_capability",
        )
    if cfg.adapter not in OPENAI_LIKE:
        return CheckResult("PARAM-06", BLOCKED, "当前协议未实现多候选检查", "仅 OpenAI Chat Completions 的 n 参数", blocker_reason="executor_not_implemented_for_adapter")
    result = await _post(cfg, _base_spec(cfg, prompt="只回复 OK", max_tokens=16, temperature=0, body={"n": 2}))
    if result.status is None:
        return CheckResult("PARAM-06", NOT_TESTED, "请求未完成", result.error)
    if 400 <= result.status < 500:
        status, actual, blocker = capability_verdict(result, ("n ", "candidate", "choices", "num_return", "parameter"))
        return CheckResult("PARAM-06", status, actual, _brief(result.error_message() or result.text), blocker)
    if not result.ok:
        return CheckResult("PARAM-06", FAIL, f"请求异常（HTTP {result.status}）", _brief(result.text))
    choices = result.json_body.get("choices")
    count = len(choices) if isinstance(choices, list) else 0
    indexes = [c.get("index") for c in choices if isinstance(c, dict)] if isinstance(choices, list) else []
    ok = count >= 2 and len(set(indexes)) == count
    return CheckResult("PARAM-06", PASS if ok else FAIL, f"返回 {count} 个候选，索引 {indexes}", "候选数量与索引应完整且唯一" if not ok else "多候选数量与索引正确")


async def check_param_conflict(cfg: SuiteConfig) -> CheckResult:
    """PARAM-08：互斥/冲突参数必须被明确拒绝，不能静默忽略后照常回答。

    构造：强制调用工具（required / any）但不提供任何工具定义。
    """
    choice = {"type": "any"} if cfg.adapter == ANTHROPIC else "required"
    result = await _post(
        cfg,
        _base_spec(cfg, prompt="北京天气如何？", max_tokens=64, temperature=0, body={"tool_choice": choice}),
    )
    if result.status is None:
        return CheckResult("PARAM-08", NOT_TESTED, "请求未完成", result.error)
    if 500 <= result.status < 600:
        return CheckResult("PARAM-08", BLOCKED, f"上游返回 HTTP {result.status}（服务端故障，无法判定）", _brief(result.text), "upstream_unavailable")
    rejected = 400 <= result.status < 500
    if rejected:
        return CheckResult("PARAM-08", PASS, f"冲突参数被明确拒绝（HTTP {result.status}）", _brief(result.error_message() or result.text))
    if result.ok:
        return CheckResult("PARAM-08", FAIL, "强制调用工具但未提供工具定义，请求仍返回 200", f"响应片段：{_brief(_content_text(result.json_body))}")
    return CheckResult("PARAM-08", NOT_TESTED, f"意外状态 HTTP {result.status}", _brief(result.text))


async def check_media_two_images(cfg: SuiteConfig) -> CheckResult:
    """MEDIA-03：多图输入可区分且顺序正确。"""
    if cfg.adapter not in OPENAI_LIKE:
        return CheckResult("MEDIA-03", BLOCKED, "当前协议未实现多图检查", "仅 OpenAI Chat Completions", blocker_reason="executor_not_implemented_for_adapter")
    red = f"data:image/png;base64,{_tiny_png_red()}"
    blue = f"data:image/png;base64,{_tiny_png_rgb((0, 0, 255))}"
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "依次说出两张图片的颜色。"},
                    {"type": "image_url", "image_url": {"url": red}},
                    {"type": "image_url", "image_url": {"url": blue}},
                ],
            }
        ]
    }
    result = await _post(cfg, _base_spec(cfg, prompt="", max_tokens=48, temperature=0, body=body))
    if result.status is None:
        return CheckResult("MEDIA-03", NOT_TESTED, "请求未完成", result.error)
    if not result.ok:
        return CheckResult("MEDIA-03", NOT_APPLICABLE, f"模型不支持多图输入（HTTP {result.status}）", _brief(result.error_message() or result.text))
    text = _content_text(result.json_body)
    ok = "红" in text and "蓝" in text
    return CheckResult("MEDIA-03", PASS if ok else FAIL, f"两张图片{'均被区分' if ok else '未被正确区分'}", f"响应片段：{_brief(text)}")


async def check_struct_invalid_schema(cfg: SuiteConfig) -> CheckResult:
    """STRUCT-03：非法 Schema 必须明确报错，不得静默退回纯文本。"""
    if cfg.adapter not in OPENAI_LIKE:
        return CheckResult("STRUCT-03", BLOCKED, "当前协议未实现该检查", "仅 OpenAI Chat Completions 的 json_schema", blocker_reason="executor_not_implemented_for_adapter")
    bad = {
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "broken", "strict": True, "schema": {"type": "not-a-real-type", "properties": {}}},
        }
    }
    result = await _post(cfg, _base_spec(cfg, prompt="输出 JSON。", max_tokens=64, temperature=0, body=bad))
    if result.status is None:
        return CheckResult("STRUCT-03", NOT_TESTED, "请求未完成", result.error)
    rejected = 400 <= result.status < 500
    return CheckResult(
        "STRUCT-03",
        PASS if rejected else FAIL,
        f"非法 Schema {'被明确拒绝' if rejected else '未被拒绝'}（HTTP {result.status}）",
        _brief(result.error_message() or _content_text(result.json_body)),
    )


async def check_model_reported(cfg: SuiteConfig) -> CheckResult:
    """ID-04 / ROUTE-01：响应中的模型标识与请求一致，无未说明的替换。"""
    result = await _post(cfg, _base_spec(cfg, prompt="只回复 OK", max_tokens=16, temperature=0))
    if result.status is None:
        return CheckResult("ID-04", NOT_TESTED, "请求未完成", result.error)
    if not result.ok:
        return CheckResult("ID-04", FAIL, f"请求失败（HTTP {result.status}）", _brief(result.error_message() or result.text))
    reported = str(result.json_body.get("model") or "")
    candidates = result.json_body.get("candidates")
    if not reported and isinstance(candidates, list) and candidates:
        reported = str((candidates[0] or {}).get("modelVersion") or "") if isinstance(candidates[0], dict) else ""
    if not reported:
        return CheckResult("ID-04", NOT_TESTED, "响应未返回模型标识", "协议未提供 model 字段，无法核对")
    ok = reported == cfg.model
    return CheckResult("ID-04", PASS if ok else FAIL, f"响应模型标识 {reported}（请求 {cfg.model}）", "标识不一致需供应商说明映射依据" if not ok else "标识与请求一致")


# ---------------------------------------------------------------------------
# 0. 前置必测（GATE）：先跑这三条，任一不通过就判不达标，后续测试不再执行
# ---------------------------------------------------------------------------
#: 缓存命中率统计的重复次数（标准要求连发 5～10 次，默认取 5，可用项参数覆盖）
#: 与《供应商大模型自动化测试套件 v1.7》门禁口径对齐（2026-11-02）
#: G1 连通：1 次非流式（必须回 G1_OK）+ 1 次流式（有内容且正常结束）
#: G2 缓存：约 3000 token 前缀连发 6 次，除首次写入外，后 5 次必须全部命中（命中率 = 1）
#: G3 延时：连发 20 次，全部成功，且中位延时 ≤ 10s
GATE_CACHE_PREFIX_TOKENS = 3000
GATE_CACHE_SENDS = 6
GATE_CACHE_INTERVAL = 1.0
GATE_LATENCY_RUNS = 20
GATE_LATENCY_LIMIT_S = 10.0
GATE_CALL_MAX_TOKENS = 300
GATE_CACHE_MAX_TOKENS = 24
#: 碰到 429/5xx 时的重试次数与退避基数（秒）：上游抖动不该记成渠道不达标
GATE_RETRY_ATTEMPTS = 2
GATE_RETRY_BACKOFF = 2.0
#: 兼容旧测试/旧参数名
GATE_CACHE_CALLS = GATE_CACHE_SENDS
GATE_LATENCY_SAMPLES = GATE_LATENCY_RUNS
GATE_MIN_SAMPLES = GATE_LATENCY_RUNS

#: 固定语料：与套件里的 NAT 一致，按 32 字符/token 近似生成长前缀。
#: 真实 token 数以 usage 里的 cache_creation / cache_read（W/R）为准。
_GATE_NAT = (
    "This document provides background context for a capability and cache behavior study.\n\n"
    "The Baltic Sea has served as a major corridor for northern European commerce since the "
    "Viking era. Merchants from Lubeck, Gdansk, and Riga established the Hanseatic League, "
    "which dominated regional trade from the thirteenth through the seventeenth century. Their "
    "ships carried amber southward in exchange for salt, cloth, and spices.\n\n"
    "Harbor guilds in each port maintained meticulous records of vessel arrivals and cargo "
    "manifests, archived in municipal repositories. Studies of the Lubeck archive alone have "
    "catalogued more than forty thousand individual voyage records spanning three centuries.\n\n"
    "Seasonal patterns shaped everything. Ice closed the northern ports from November until "
    "late March, compressing the sailing season into a tight summer window.\n\n"
)


def _gate_cache_prefix(tokens: int = GATE_CACHE_PREFIX_TOKENS) -> str:
    return _GATE_NAT * max(1, tokens * 32 // len(_GATE_NAT) + 1)


def _gate_ms(seconds: float) -> int:
    return int(round(seconds * 1000))


def _gate_percentile(values: list[float], q: float) -> float | None:
    """最近秩分位，与套件 ``p(q)`` 口径一致：xs[round(q*(n-1))]。"""
    if not values:
        return None
    xs = sorted(values)
    index = max(0, min(len(xs) - 1, int(round(q * (len(xs) - 1)))))
    return xs[index]


def _gate_evidence(**payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False)


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _gate_kind(outcome: "CallOutcome") -> tuple[str, str]:
    """把一次失败归成人类能看懂的一句话（ok / throttled / unavailable / rejected）。"""
    status = outcome.http_status
    if status is None:
        return "unavailable", f"连接失败或超时：{_brief(outcome.error_message or outcome.error_code or '无响应', 80)}"
    if status == 429:
        return "throttled", "HTTP 429 上游限流（请求太密或额度用尽）"
    if status >= 500:
        detail = _brief(outcome.error_message or outcome.error_body_preview, 60)
        return "unavailable", f"HTTP {status} 上游不可用" + (f"：{detail}" if detail else "")
    if status >= 300 or not outcome.ok:
        detail = _brief(outcome.error_message or outcome.error_code or outcome.error_body_preview, 80)
        return "rejected", f"HTTP {status}" + (f"：{detail}" if detail else "")
    return "ok", f"HTTP {status}"


async def _gate_call(cfg: SuiteConfig, spec: CallSpec, *, attempts: int | None = None, backoff: float | None = None):
    """门禁专用调用：限流/5xx 自动退避重试一次，别把上游抖动记成渠道不达标。"""
    attempts = GATE_RETRY_ATTEMPTS if attempts is None else attempts
    backoff = GATE_RETRY_BACKOFF if backoff is None else backoff
    outcome = await _call(cfg, spec)
    tries = 1
    while tries < attempts and _gate_kind(outcome)[0] in {"throttled", "unavailable"}:
        await asyncio.sleep(backoff * tries)
        outcome = await _call(cfg, spec)
        tries += 1
    return outcome, tries


async def check_gate_connectivity(cfg: SuiteConfig) -> CheckResult:
    """GATE-01：一次非流式 + 一次流式调用都正常才算连通。

    与套件 G1 一致：非流式必须回 `G1_OK`；流式必须有内容且正常结束（没有被截断）。
    429 限流单独标阻塞——那是平台被限速，不是渠道调不通。
    """
    sync_outcome, sync_tries = await _gate_call(
        cfg, _base_spec(cfg, prompt="Reply exactly: G1_OK", max_tokens=GATE_CALL_MAX_TOKENS, temperature=0)
    )
    sync_kind, sync_reason = _gate_kind(sync_outcome)
    if sync_kind == "throttled":
        return CheckResult(
            "GATE-01",
            BLOCKED,
            f"调用被上游限流，无法判断连通性：{sync_reason}" + (f"（已重试 {sync_tries - 1} 次）" if sync_tries > 1 else ""),
            _gate_evidence(stage="sync", http_status=sync_outcome.http_status, kind=sync_kind, attempts=sync_tries),
            blocker_reason="upstream_unavailable",
        )
    if sync_kind != "ok":
        return CheckResult(
            "GATE-01",
            FAIL,
            f"非流式调用未通过：{sync_reason}" + (f"（已重试 {sync_tries - 1} 次）" if sync_tries > 1 else ""),
            _gate_evidence(
                stage="sync",
                http_status=sync_outcome.http_status,
                kind=sync_kind,
                attempts=sync_tries,
                detail=_brief(sync_outcome.error_message or sync_outcome.error_body_preview, 200),
            ),
        )
    sync_ok = "G1_OK" in (sync_outcome.text or "")
    if not sync_ok:
        return CheckResult(
            "GATE-01",
            FAIL,
            f"非流式调用有响应但未按要求返回 G1_OK（实际「{_brief(sync_outcome.text, 40)}」）",
            _gate_evidence(stage="sync", http_status=sync_outcome.http_status, kind="marker_missing"),
        )

    stream_outcome, stream_tries = await _gate_call(
        cfg,
        _base_spec(cfg, prompt="Say: STREAM_OK", max_tokens=GATE_CALL_MAX_TOKENS, temperature=0, stream=True),
    )
    stream_kind, stream_reason = _gate_kind(stream_outcome)
    if stream_kind == "throttled":
        return CheckResult(
            "GATE-01",
            BLOCKED,
            f"流式调用被上游限流，无法判断连通性：{stream_reason}",
            _gate_evidence(stage="stream", http_status=stream_outcome.http_status, kind=stream_kind),
            blocker_reason="upstream_unavailable",
        )
    stream_ok = (
        stream_kind == "ok"
        and bool((stream_outcome.text or "").strip())
        and stream_outcome.stream_terminated
    )
    evidence = _gate_evidence(
        stage="both",
        sync={"http_status": sync_outcome.http_status, "latency_ms": sync_outcome.latency_ms, "ok": sync_ok},
        stream={
            "http_status": stream_outcome.http_status,
            "events": stream_outcome.chunk_count,
            "terminated": stream_outcome.stream_terminated,
            "ok": stream_ok,
        },
        attempts=stream_tries,
    )
    if not stream_ok:
        if stream_kind != "ok":
            reason = f"流式调用未通过：{stream_reason}"
        elif not (stream_outcome.text or "").strip():
            reason = "流式调用没有返回任何内容"
        else:
            reason = "流式调用未收到正常结束信号（可能被截断或中断）"
        return CheckResult("GATE-01", FAIL, f"非流式正常，{reason}", evidence)
    return CheckResult(
        "GATE-01",
        PASS,
        f"非流式与流式均正常（非流式 {sync_outcome.latency_ms}ms，流式 {stream_outcome.chunk_count} 个事件）",
        evidence,
    )


async def _cache_call(
    cfg: SuiteConfig, anthropic: bool, prefix: str
) -> tuple[str, str, int, int | None, int | None]:
    """发一次缓存探测请求，返回 (kind, reason, tries, 读到缓存 tokens, 写入缓存 tokens)。"""
    if anthropic:
        spec = _base_spec(
            cfg,
            prompt="Reply: ACK",
            max_tokens=GATE_CACHE_MAX_TOKENS,
            temperature=0,
            body={"system": [{"type": "text", "text": prefix, "cache_control": {"type": "ephemeral"}}]},
        )
    else:
        spec = _base_spec(cfg, system=prefix, prompt="Reply: ACK", max_tokens=GATE_CACHE_MAX_TOKENS, temperature=0)
    outcome, tries = await _gate_call(cfg, spec)
    kind, reason = _gate_kind(outcome)
    if kind != "ok":
        return kind, reason, tries, None, None
    usage = outcome.usage or {}
    if anthropic:
        return (
            "ok",
            "",
            tries,
            _as_int(usage.get("cache_read_input_tokens")),
            _as_int(usage.get("cache_creation_input_tokens")),
        )
    details = usage.get("prompt_tokens_details") if isinstance(usage.get("prompt_tokens_details"), dict) else {}
    return "ok", "", tries, _as_int(details.get("cached_tokens")), None


async def _cache_sequence(
    cfg: SuiteConfig,
    anthropic: bool,
    prefix: str,
    sends: int,
    *,
    first: tuple[str, str, int, int | None, int | None] | None = None,
) -> dict[str, Any]:
    """连发 sends 次，收集每次的读写令牌。

    ``first`` 可传入已完成的首次结果（自动回退时第一次已经发过了，不重复计费）。
    """
    reads: list[int | None] = []
    writes: list[int | None] = []
    failures: list[str] = []
    throttled = 0

    for index in range(sends):
        if index == 0 and first is not None:
            kind, reason, tries, read, write = first
        else:
            kind, reason, tries, read, write = await _cache_call(cfg, anthropic, prefix)
        if kind != "ok":
            if kind == "throttled":
                throttled += 1
            failures.append(f"第 {index + 1} 次：{reason}" + (f"（重试 {tries - 1} 次）" if tries > 1 else ""))
            reads.append(None)
            writes.append(None)
            continue
        reads.append(read)
        writes.append(write)
        if index + 1 < sends:
            await asyncio.sleep(GATE_CACHE_INTERVAL)

    return {
        "reads": reads,
        "writes": writes,
        "failures": failures,
        "throttled": throttled,
    }


async def _cache_attempt(
    cfg: SuiteConfig, anthropic: bool, prefix: str, sends: int
) -> dict[str, Any]:
    """跑一整轮缓存探测（1 次写入 + sends-1 次读取），返回该轮的读写记录。"""
    seq = await _cache_sequence(cfg, anthropic, prefix, sends)
    measured = sends - 1
    hits = sum(1 for value in seq["reads"][1:] if value and value > 0)
    return {
        "anthropic": anthropic,
        "cfg": cfg,
        "reads": seq["reads"],
        "writes": seq["writes"],
        "failures": seq["failures"],
        "throttled": seq["throttled"],
        "hits": hits,
        "measured": measured,
        "rate": (hits / measured) if measured else 0.0,
    }


def _cache_wrote(attempt: dict[str, Any]) -> int:
    return int((attempt["writes"][0] if attempt["writes"] else 0) or 0)


def _cache_attempt_label(attempt: dict[str, Any]) -> str:
    return "anthropic-cache_control" if attempt["anthropic"] else "openai-auto-cache"


async def check_gate_cache_hit(cfg: SuiteConfig) -> CheckResult:
    """GATE-02：先**显式写入缓存**，再用相同输入连发验证命中。

    规则（与套件 G2 一致，2026-11-02 按线上问题补齐）：

    * Claude / Anthropic 模型：缓存必须由请求里的 ``cache_control`` 触发写入
      （``ephemeral``，默认 5 分钟 TTL）。所以第一发就是“建缓存”，随后 5 次必须全部
      ``cache_read``；即使任务里选的是 OpenAI 兼容协议，也会自动改用 ``/v1/messages``
      去写，因为 OpenAI 协议没有这个字段、网关不会替你建缓存。
    * 其它模型：走 OpenAI 自动前缀缓存，第 2 发起 ``cached_tokens`` 必须恒大于 0；
      全 0 时再按 Anthropic 显式缓存补一轮。
    """
    prefix = _gate_cache_prefix()
    sends = GATE_CACHE_SENDS
    anthropic_adapter = str(cfg.adapter or "").lower() == "anthropic"
    model_name = str(getattr(cfg, "model", "") or "").lower()
    claude_like = "claude" in model_name or "anthropic" in model_name

    from dataclasses import replace

    explicit_cfg = cfg if anthropic_adapter else replace(cfg, adapter="anthropic")
    explicit_first = anthropic_adapter or claude_like

    if explicit_first:
        primary = await _cache_attempt(explicit_cfg, True, prefix, sends)
        if not anthropic_adapter:
            primary["label"] = "anthropic-cache_control（按 Claude 模型自动显式写入）"
        else:
            primary["label"] = "anthropic-cache_control"
    else:
        primary = await _cache_attempt(cfg, False, prefix, sends)
        primary["label"] = "openai-auto-cache"

    result = primary
    fallback: dict[str, Any] = {}

    # 第一轮既没写入也没命中，才换另一种协议再试一次；限流/请求失败不重试。
    primary_stuck = (
        primary["hits"] == 0
        and not primary["throttled"]
        and not primary["failures"]
        and (
            primary["anthropic"] and _cache_wrote(primary) == 0 or not primary["anthropic"]
        )
    )
    if primary["hits"] < primary["measured"] and primary_stuck:
        if primary["anthropic"]:
            secondary = await _cache_attempt(cfg, False, prefix, sends)
            secondary["label"] = "openai-auto-cache（显式缓存未写入后的兜底）"
        else:
            secondary = await _cache_attempt(explicit_cfg, True, prefix, sends)
            secondary["label"] = "anthropic-cache_control（自动缓存未命中后的回退）"
        fallback = {
            "attempted": True,
            "mode": secondary["label"],
            "hits": secondary["hits"],
            "wrote": _cache_wrote(secondary),
            "failures": secondary["failures"][:1],
        }
        # 第二轮更好才采用：命中更多，或第一轮根本没写入而第二轮写进去了
        if secondary["hits"] > primary["hits"] or (
            _cache_wrote(primary) == 0 and _cache_wrote(secondary) > 0 and secondary["hits"] >= primary["hits"]
        ):
            result = secondary

    reads = result["reads"]
    writes = result["writes"]
    failures = result["failures"]
    throttled = result["throttled"]
    hits = result["hits"]
    measured = result["measured"]
    rate = result["rate"]
    first_write = _cache_wrote(result)
    zeros = [value for value in reads if value == 0]

    evidence = _gate_evidence(
        mode=result["label"],
        sends=sends,
        measured=measured,
        hits=hits,
        hit_rate=round(rate, 3),
        cache_read_tokens=reads,
        cache_write_tokens=writes,
        failures=failures,
        throttled=throttled,
        zeros=len(zeros),
        wrote_tokens=first_write,
        fallback=fallback,
        primary_mode=primary["label"],
        prefix_tokens_estimate=GATE_CACHE_PREFIX_TOKENS,
        note="第一发负责写入缓存（cache_creation），后续相同输入必须读到 cache_read / cached_tokens；"
        "首次写入不计入命中率",
    )

    if throttled:
        return CheckResult(
            "GATE-02",
            BLOCKED,
            f"命中率不可判定：{sends} 次请求中有 {throttled} 次被上游限流（HTTP 429）",
            evidence,
            blocker_reason="upstream_unavailable",
        )
    if failures and hits == 0:
        return CheckResult(
            "GATE-02",
            FAIL,
            f"缓存写入/读取请求失败：{failures[0]}",
            evidence,
        )
    if hits == measured:
        wrote_text = f"{first_write} tokens" if first_write else "自动缓存"
        return CheckResult(
            "GATE-02",
            PASS,
            f"缓存命中率 1（第 1 次写入 {wrote_text}，随后 {hits}/{measured} 次全部读到缓存）",
            evidence,
        )

    # 没通过：按“卡在哪一步”给不同的说明
    if result["anthropic"] and first_write == 0 and hits == 0:
        extra = f"；另一路径：{fallback['mode']}，{fallback.get('failures') or '未命中'}" if fallback else ""
        return CheckResult(
            "GATE-02",
            FAIL,
            "缓存没有写入：第 1 次请求的 cache_creation=0，后续没有可命中的缓存"
            "（该端点可能未透传 cache_control，或该模型未启用缓存）" + extra,
            evidence,
        )
    if zeros:
        hint = (
            "响应返回 cached_tokens=0：渠道没有对相同输入建立自动缓存。"
            "已按 /v1/messages + cache_control 显式写入再验证："
            f"{fallback.get('mode') if fallback else '未尝试'}"
        )
        return CheckResult("GATE-02", FAIL, f"缓存命中率 {rate:.2f}（{hits}/{measured}）：{hint}", evidence)
    if all(value is None for value in reads):
        return CheckResult(
            "GATE-02",
            FAIL,
            "请求都成功，但响应里没有缓存用量字段（cached_tokens / cache_read_input_tokens），无法确认命中",
            evidence,
        )
    return CheckResult(
        "GATE-02",
        FAIL,
        f"缓存命中率 {rate:.2f}（{hits}/{measured}，{measured - hits} 次重复请求没读到缓存：{reads[1:]}）",
        evidence,
    )


async def check_gate_latency(cfg: SuiteConfig) -> CheckResult:
    """GATE-03：连发 20 次，全部成功且中位延时 ≤ 10s。

    与套件 G3 一致：成功率必须是 100%（一次失败即不通过），分位按最近秩计算。
    分位数随任务落库，作为后续该渠道的权重依据。
    """
    runs = GATE_LATENCY_RUNS
    limit_s = GATE_LATENCY_LIMIT_S
    durations: list[float] = []
    failures: list[str] = []
    throttled = 0

    for index in range(runs):
        outcome, tries = await _gate_call(
            cfg, _base_spec(cfg, prompt="Reply: OK", max_tokens=GATE_CALL_MAX_TOKENS, temperature=0)
        )
        kind, reason = _gate_kind(outcome)
        if kind != "ok":
            if kind == "throttled":
                throttled += 1
            failures.append(f"第 {index + 1} 次：{reason}" + (f"（重试 {tries - 1} 次）" if tries > 1 else ""))
            continue
        durations.append(outcome.latency_ms / 1000.0)

    success_rate = len(durations) / runs if runs else 0.0
    evidence = _gate_evidence(
        success_rate=round(success_rate, 3),
        samples=len(durations),
        requested=runs,
        failures=failures[:5],
        throttled=throttled,
        limit_ms=_gate_ms(limit_s),
    )

    if len(durations) < runs:
        status = BLOCKED if throttled else FAIL
        first = failures[0] if failures else "未知原因"
        return CheckResult(
            "GATE-03",
            status,
            f"延时测试未全部成功（{len(durations)}/{runs}），{first}",
            evidence,
            blocker_reason="upstream_unavailable" if status == BLOCKED else "",
        )

    p5 = _gate_percentile(durations, 0.05) or 0.0
    p50 = _gate_percentile(durations, 0.50) or 0.0
    p95 = _gate_percentile(durations, 0.95) or 0.0
    evidence = _gate_evidence(
        success_rate=1.0,
        samples=len(durations),
        requested=runs,
        p5_ms=_gate_ms(p5),
        p50_ms=_gate_ms(p50),
        p95_ms=_gate_ms(p95),
        max_ms=_gate_ms(max(durations)),
        limit_ms=_gate_ms(limit_s),
    )
    actual = f"P5 {p5:.2f}s · 中位 {p50:.2f}s · P95 {p95:.2f}s（{runs}/{runs} 次成功）"
    if p50 > limit_s:
        return CheckResult("GATE-03", FAIL, f"{actual}，中位超过 {limit_s:.0f}s", evidence)
    return CheckResult("GATE-03", PASS, actual, evidence)


CHECKS: dict[str, Callable[[SuiteConfig], Awaitable[CheckResult]]] = {
    # 0. 前置必测（优先执行；任一不通过即判不达标）
    "gate_connectivity": check_gate_connectivity,
    "gate_cache_hit": check_gate_cache_hit,
    "gate_latency": check_gate_latency,
    # 2.3 基础消息
    "msg_marker": check_msg_marker,
    "msg_multiturn": check_msg_multiturn,
    "msg_assistant_history": check_msg_assistant_history,
    "system_rule": check_system_rule,
    "msg_multi_block": check_msg_multi_block,
    "msg_string_vs_array": check_msg_string_vs_array,
    "msg_special_chars": check_msg_special_chars,
    # 2.4 长上下文
    "ctx_long_system": check_ctx_long_system,
    "ctx_long_user": check_ctx_long_user,
    "ctx_multi_turn": check_ctx_multi_turn,
    "ctx_near_limit": check_ctx_near_limit,
    "ctx_over_limit": check_ctx_over_limit,
    # 2.5 参数
    "param_max_tokens": check_param_max_tokens,
    "param_temperature": check_param_temperature,
    "param_stop": check_param_stop,
    "stream_switch": check_stream_switch,
    "param_stream_usage": check_param_stream_usage,
    "param_unknown_field": check_param_unknown_field,
    "param_conflict": check_param_conflict,
    # 2.6 工具
    "tool_basic": check_tool_basic,
    "tool_auto": check_tool_auto,
    "tool_required": check_tool_required,
    "tool_none": check_tool_none,
    "tool_roundtrip": check_tool_roundtrip,
    "tool_multi": check_tool_multi,
    "tool_stream_args": check_tool_stream_args,
    "tool_bad_id": check_tool_bad_id,
    # 2.7 图片
    "media_data_url": check_media_data_url,
    "media_invalid": check_media_invalid,
    # 2.8 结构化
    "struct_json": check_struct_json,
    "struct_schema": check_struct_schema,
    # 2.9 流式
    "sse_parse": check_sse_parse,
    "sse_concat": check_sse_concat,
    "sse_finish_reason": check_sse_finish_reason,
    "sse_usage": check_sse_usage,
    # 2.10 非法请求
    "invalid_json": check_invalid_json,
    "missing_field": check_missing_field,
    "field_type_error": check_field_type_error,
    "invalid_role": check_invalid_role,
    "error_shape": check_error_shape,
    # 3.4 / 4.5 / 4.8
    "cache_hit": check_cache_hit,
    "cap_text": check_cap_text,
    "cap_multilingual": check_cap_multilingual,
    "consistency": check_consistency,
    # 2.3 / 2.5 / 2.6 / 2.7 / 2.8 / 4.3
    "msg_developer_role": check_msg_developer_role,
    "param_n_choices": check_param_n_choices,
    "media_two_images": check_media_two_images,
    "struct_invalid_schema": check_struct_invalid_schema,
    "model_reported": check_model_reported,
}


_CAP_HTML_RE = re.compile(r"<html|<!doctype|<body", re.I)


def _mentions(text: str, needles: tuple[str, ...]) -> bool:
    """错误体是否**指向**该参数/角色/能力。

    短 token（<=3 字符，如 `n`、`id`）必须独立成词，否则 "n" 会命中 mention、
    invalid 里的 n，等于没判。
    """
    lowered = (text or "").lower()
    if not lowered:
        return False
    stripped = lowered.replace("\n", " ").replace("\t", " ")
    words = {part.strip(" :,\"'{}[]()<>=.;!") for part in stripped.split(" ") if part.strip()}
    for needle in needles:
        token = needle.lower().strip()
        if not token:
            continue
        if len(token) <= 3:
            if token in words:
                return True
        elif token in lowered:
            return True
    return False


def capability_verdict(result: RawResult, needles: tuple[str, ...]) -> tuple[str, str, str]:
    """Q10 三态：上游对"该能力"的响应如何归类。

    * 4xx + 错误体**指向该参数/角色/能力**（非空、非 HTML） → ``pass``
      原文允许"不支持时明确拒绝"，老实拒绝就合格，不能一锅端成不适用；
    * 4xx 但归因不明（空体 / 通用 400 / HTML 登录页）       → ``pending``（na_candidate）
    * 5xx / 没有响应（超时、连接失败、断流）                → ``blocked``（配套 blocker_reason）

    返回 ``(status, actual, blocker_reason)``。
    """
    status = result.status
    body = (result.text or "").strip()
    if status is None:
        return BLOCKED, "请求未完成（超时/连接失败），无法判定该能力", "upstream_unavailable"
    if 500 <= status < 600:
        return BLOCKED, f"上游返回 HTTP {status}（服务端故障，无法判定该能力）", "upstream_unavailable"
    if 400 <= status < 500:
        if not body or _CAP_HTML_RE.search(body):
            return (
                PENDING,
                f"HTTP {status} 但错误体为空或为 HTML，归因不明（na_candidate）",
                "",
            )
        if _mentions(body, needles):
            return PASS, f"HTTP {status}，错误体明确指向 {'/'.join(needles)}（拒绝即合格）", ""
        return PENDING, f"HTTP {status}，错误体未指向 {'/'.join(needles)}（归因不明）", ""
    return NOT_TESTED, f"HTTP {status}，未按预期拒绝或报错", ""


async def run_auto_checks(cfg: SuiteConfig, items: list[Any], emit: Emit) -> list[CheckResult]:
    """Run every enabled auto item, bounded by the model concurrency setting."""
    semaphore = asyncio.Semaphore(max(1, min(4, settings.model_max_concurrency)))
    results: list[CheckResult] = []

    async def one(item) -> None:
        check = CHECKS.get(item.auto_check or "")
        if check is None:
            return
        await emit("item_start", {"item_id": item.id, "name": item.name})
        async with semaphore:
            token = _ITEM_PARAMS.set(dict(getattr(item, "params", {}) or {}))
            try:
                result = await check(cfg)
            except Exception as exc:  # noqa: BLE001 - 单项异常不影响其它项
                result = CheckResult(item.id, NOT_TESTED, "执行异常", _brief(exc))
            finally:
                _ITEM_PARAMS.reset(token)
        # 同一检查可能被多个测试项复用（如 ID-04 / ROUTE-01），结果必须归属当前测试项
        result = CheckResult(item.id, result.status, result.actual, result.evidence, result.blocker_reason)
        results.append(result)
        await emit(
            "item",
            {
                "item_id": item.id,
                "status": result.status,
                "actual": result.actual,
                "evidence": result.evidence,
                "source": "auto",
                "blocker_reason": result.blocker_reason,
                "note": result.note,
            },
        )

    await asyncio.gather(*(one(item) for item in items))
    return results
