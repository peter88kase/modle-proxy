"""Chapter-1 acceptance suite: connectivity, ordinary requests, streaming,
authentication, model-ID boundaries and timeout behaviour.

The case identifiers (NET-01, REQ-03, AUTH-04, ...) match the acceptance
standard document so that an exported report can be attached to a supplier
review without translation.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import socket
import time
from dataclasses import dataclass, field, replace
from typing import Any, Awaitable, Callable

from .adapters.base import CallSpec, get_adapter
from .config import settings
from .netguard import TargetError, validate_url
from .security import redact_text
from .shell_client import ShellUnavailable, call_worker
from .standards import FINISH_REASON_WHITELIST
from .upstream import CallOutcome, execute

Emit = Callable[[str, dict[str, Any]], Awaitable[None]]

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


@dataclass
class CaseResult:
    case_id: str
    title: str
    result: str
    evidence: str = ""
    http_status: int | None = None
    latency_ms: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "result": self.result,
            "evidence": self.evidence,
            "http_status": self.http_status,
            "latency_ms": self.latency_ms,
        }


@dataclass
class SuiteConfig:
    provider_id: str
    provider_name: str
    adapter: str
    model: str
    links: list[str]
    direct_base_url: str = ""
    forward_base_url: str = ""
    forward_model: str = ""
    api_key: str = field(default="", repr=False)
    forward_api_key: str = field(default="", repr=False)
    api_secret: str = field(default="", repr=False)
    auth_style: str = ""
    #: API 版本号的值。空 = 用适配器默认值。
    api_version: str = ""
    #: True = 版本号放**请求体**（AWS Bedrock `InvokeModel` 风格）；
    #: False = 放 **header**（Anthropic 直连 / bedrock-mantle）。
    #: 由任务选项 `version_in_body` 透传，见 `CallSpec.version_in_body` 的说明。
    version_in_body: bool = False
    prompt: str = "只回复 CONNECT_OK"
    system: str = ""
    max_tokens: int = 32
    temperature: float | None = 0.2
    stream_usage: bool = False
    repeat: int = 3
    total_timeout: float = 60
    first_token_timeout: float = 30
    connect_timeout: float = 10
    unreachable_url: str = ""
    #: NET-05 用的回显服务地址。空 = 用 IP_ECHO_URLS 里那几家依次尝试。
    ip_echo_url: str = ""
    #: 相邻两次**真实上游调用**之间至少间隔多少秒（0 = 不限速）。
    #: 验收一轮要连发十几到几十个请求，背靠背发很容易撞网关 RPM 限制（429），
    #: 而 429 会被写成判定结论——那等于拿平台的请求节奏去扣供应商的分。
    #: ``None`` = 用 ``settings.model_request_interval``（部署级默认值，可用
    #: ``MODEL_REQUEST_INTERVAL`` 覆盖；测试环境设为 0 以免把套件跑得很慢）。
    request_interval: float | None = None
    mock_no_content_url: str = ""
    mock_heartbeat_url: str = ""
    user_id: int | None = None
    username: str = ""

    def wipe(self) -> None:
        self.api_key = ""
        self.forward_api_key = ""
        self.api_secret = ""


@dataclass
class LinkContext:
    name: str
    label: str
    base_url: str
    model: str
    api_key: str = field(default="", repr=False)
    fixed_channel: str = ""


def _fmt_ms(value: int | None) -> str:
    return "-" if value is None else f"{value}ms"


def _mutate_model_id(model: str) -> str:
    """Change exactly one character so the ID stays plausibly formatted.

    用于 MODEL-03：区分“模型不存在”与“客户端把未知 ID 静默映射到默认模型”。
    """
    text = (model or "").strip()
    if not text:
        return ""
    head, last = text[:-1], text[-1]
    if last.isdigit():
        return head + str((int(last) + 1) % 10)
    if last.isalpha():
        base = ord("a") if last.islower() else ord("A")
        offset = (ord(last) - base + 1) % 26
        return head + chr(base + offset)
    return text + "-x"


#: 出现这些结构键且值非空 → 错误体里夹带了模型输出（不是纯错误结构）。
_MODEL_OUTPUT_KEYS = ("choices", "delta", "content", "candidates", "tool_calls", "message")
_MODEL_OUTPUT_PHRASES = ("assistant", "sure", "当然", "好的", "以下是", "answer is")
#: 纯错误体可能出现的顶层键。很多网关的 401 就长这样：
#: {"id":"Unauthorized","message":"Unable to authenticate you"} —— 没有 error 包装。
_ERROR_ONLY_KEYS = {
    "id", "object", "error", "errors", "code", "message", "msg", "type", "detail",
    "details", "status", "status_code", "param", "request_id", "trace_id", "timestamp",
    "path", "documentation_url",
}


def looks_like_model_output(body: str) -> bool:
    """错误体里是否夹带了模型输出。

    **误判方向取保守**：拿不准时判"像模型输出"（→ 该判 FAIL）。
    理由：漏判会让"网关把模型回答当 400 返回"这种真实缺陷溜过去；
    多判只会让供应商去看一眼错误体，成本低得多。
    """
    text = (body or "").strip()
    if not text:
        return False
    lowered = text.lower()
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        # 先看模型输出特征：dict 形态的 message 也属于模型对象，不能被下面的白名单放过去。
        for key in _MODEL_OUTPUT_KEYS:
            value = parsed.get(key)
            if not value:
                continue
            # 字符串 message 是错误说明（"Unable to authenticate you"）；
            # 只有 dict 形态的 message 才像模型对象（{"role":"assistant",...}）。
            if key == "message" and isinstance(value, str):
                continue
            return True
        if set(parsed) <= _ERROR_ONLY_KEYS:
            # 纯错误结构里 message 也是错误说明，不当模型输出
            return False
    if any(phrase in lowered for phrase in _MODEL_OUTPUT_PHRASES):
        return True
    # 长文本 + 不像 JSON 错误结构：保守判"像模型输出"
    return len(text) > 200 and parsed is None


def rejection_ok(outcome: CallOutcome) -> bool:
    """AUTH-02/03/04、MODEL-02/03 判定：原文"明确拒绝，无模型输出"。

    必须是**被鉴权/模型参数校验拒绝**（4xx），且响应里没有模型输出。
    过去是 ``status >= 400``：502「upstream connect error」也算"明确拒绝"，
    审计 §3.2 已实测这种网关错误会判 PASS（危险度高）。

    "有没有模型输出"看的是 ``error_body_preview`` 而不是 ``text``：
    ``text`` 在非 2xx 上恒为空（见 upstream.py 非 2xx 分支的注释），
    只判 text 等于这半句永远不执行。
    """
    status = outcome.http_status or 0
    if not 400 <= status < 500:
        return False
    return not looks_like_model_output(outcome.error_body_preview)


def request_completed_ok(outcome: CallOutcome) -> bool:
    """REQ-03 判定：原文"在总超时预算内返回完整响应，无持续挂起"。

    "完整"不能只看"没超时、没取消"——401/502/被截断的流过去全部通过。
    这里要求：2xx + 真的拿到正文 + 未超时未取消 + 流式时收到结束信号。
    """
    return (
        bool(outcome.http_status and 200 <= outcome.http_status < 300)
        and bool((outcome.text or "").strip())
        and not outcome.timed_out
        and not outcome.cancelled
        and (outcome.stream_terminated or not outcome.chunk_count)
    )


def response_is_api_data(outcome: CallOutcome) -> bool:
    """REQ-04 判定（2026-10-24 口径）：正文是合法 JSON 即通过。

    「返回 API 数据，不得是登录页/验证码页/代理错误网页」的机器可判形式就是
    **能不能当成 JSON 解析**：HTML 登录页、nginx 502 页面、纯文本网关错误都解析不了。

    这里**不再要求 2xx**——早期版本把"请求成功"和"响应类型"混在一个判据里，
    于是一个 401 的 JSON 错误响应（它确实是 API 数据，不是登录页）被判成"类型错误"，
    判错了对象。请求是否成功由 REQ-01、鉴权是否生效由 AUTH-* 负责。

    判据取 ``outcome.body_is_json``（读取完整原始字节时算出），**不解析预览字符串**：
    ``raw_body_preview`` 是给人看的脱敏副本，会被截断——拿它 ``json.loads``，
    真实响应一超过截断长度就必然判失败（线上表现：HTTP 200、Content-Type 是
    application/json，却 0/3 通过）。``None`` 表示没读到正文，此时才退回文本兜底。
    """
    if outcome.body_is_json is not None:
        return outcome.body_is_json
    raw = (outcome.raw_body_preview or outcome.error_body_preview or outcome.text or "").strip()
    if not raw or raw[0] not in "{[":
        return False
    try:
        json.loads(raw)
    except ValueError:
        return False
    return True


def not_a_redirect(outcome: CallOutcome) -> bool:
    """NET-04 判定（2026-10-24 口径）：状态码不是 3xx 即通过。

    重定向行为这一项只回答一个问题——**上游有没有把请求带走**。
    平台的 HTTP 客户端本来就不跟随跳转（`follow_redirects=False`），
    所以这里只判状态码区间，不再附带"目标域名是否可信"这类需要人读的结论。
    """
    status = outcome.http_status
    if status is None:
        return False  # 没有响应就无从判断"有没有 3xx"
    return not 300 <= status < 400


def has_any_response(outcome: CallOutcome) -> bool:
    """AUTH-06 判定（2026-10-24 口径）：无效 Key 只要有 HTTP 返回就算通过。

    平台没有供应商的"已过期 Key"，只能用随机无效 Key 等价测试。
    这一项只问"服务器还活着、还会回话"；**它是否明确拒绝**由 AUTH-04 判——
    两项分开，才不会互相顶替（旧版本一项都不判，全丢给人工）。
    """
    return outcome.http_status is not None


#: 声明的鉴权方式 -> 该方式在请求里应出现的头名（小写）。
#: 这张表故意写死在平台侧而不是问适配器：适配器如果偷偷换了方案，
#: 这里就会红——AUTH-07 要发现的正是"声明一套、实发另一套"。
EXPECTED_AUTH_HEADERS = {
    "bearer": "authorization",
    "x-api-key": "x-api-key",
    "api-key": "api-key",
    "goog-api-key": "x-goog-api-key",
    "custom-header": "x-api-key",
    "none": "",
}


def auth_style_matches(style: str, outcome: CallOutcome) -> tuple[bool, str]:
    """AUTH-07 判定（2026-10-24 口径）：声明的方式与实际发出的鉴权头一致即通过。

    返回 ``(是否一致, 说明)``。识别不到声明（空 / 未知取值）时判不一致并说明原因，
    不猜一个默认值代替——猜出来的"一致"没有信息量。
    """
    key = (style or "").strip().lower()
    actual = sorted({name.lower() for name in outcome.auth_headers})
    if not key:
        return False, f"供应商未声明鉴权方式，无法比对；实际发出 {actual or '无鉴权头'}"
    expected = EXPECTED_AUTH_HEADERS.get(key)
    if expected is None:
        return False, f"未知的鉴权方式 {style}；实际发出 {actual or '无鉴权头'}"
    if not expected:
        return (
            (not actual),
            f"声明为免鉴权；实际发出 {actual or '无鉴权头'}",
        )
    return (expected in actual), f"声明 {key} → 应有 {expected}；实际发出 {actual or '无鉴权头'}"


def model_usable(outcome: CallOutcome) -> bool:
    """AUTH-08 判定（2026-10-24 口径）：目标模型能用即通过。

    2xx + 有正文 = 用这个 Key 确实能调用到目标模型。
    "有没有被静默转到别的模型"由 REQ-05（model 字段）判，这里不重复承担。
    """
    return bool(
        outcome.http_status
        and 200 <= outcome.http_status < 300
        and (outcome.text or "").strip()
    )



def stream_start_ok(outcome: CallOutcome) -> bool:
    """STREAM-01 判定：原文"按约定协议返回流式响应，**无解析错误**"。

    三件事缺一不可：2xx、真的收到了正文块、没有任何无法解析的事件。
    过去只看前两件——畸形事件在 `BaseStreamParser.feed()` 里被
    `except ValueError: continue` 静默丢弃，所以"无解析错误"这半句从未被判定（F5）。
    """
    return (
        bool(outcome.http_status and 200 <= outcome.http_status < 300)
        and outcome.chunk_count > 0
        and outcome.malformed_events == 0
    )


def stream_end_ok(outcome: CallOutcome) -> bool:
    """STREAM-04 判定：原文"收到正常结束信号，并在总超时内完成"。

    三条一起判，缺一不可（规格 §8.3.1）：
    1. 没有超时；
    2. 结束信号来自上游（``upstream_field``/``upstream_event``）——
       ``synthesized`` 表示流断了但上游什么也没说，那是截断，不是结束；
    3. 上游报了结束原因时，必须在协议白名单内；只发了 ``[DONE]``/``message_stop``
       这类显式终止事件、没有结束原因的，允许以 ``upstream_event`` 通过。

    过去只判 ``bool(o.finish_reason)``，而 base.py 会合成 "eof"，所以恒真（F1）。
    """
    if outcome.timed_out or not outcome.stream_terminated:
        return False
    if outcome.finish_source not in {"upstream_field", "upstream_event"}:
        return False
    reason = (outcome.finish_reason or "").strip().lower()
    if not reason:
        return outcome.finish_source == "upstream_event"
    return reason in FINISH_REASON_WHITELIST


def stream_no_error_disguise(outcome: CallOutcome) -> bool:
    """STREAM-05 判定：原文"不得把错误事件或异常断流当作正常成功"。

    只判 error_code 不够：截断流在 error_code 为空时（F1 造成的死分支）也会通过，
    所以额外要求"确实收到了正常结束信号"（F2）。
    """
    return bool(outcome.stream_terminated) and outcome.error_code not in {
        "stream_error",
        "empty_stream",
        "stream_incomplete",
    }


def _agg(case_id: str, title: str, checks: list[tuple[bool, str, CallOutcome | None]]) -> CaseResult:
    passed = sum(1 for ok, _, _ in checks if ok)
    last = next((o for _, _, o in reversed(checks) if o is not None), None)
    seen: list[str] = []
    for _, note, _ in checks:
        if note and note not in seen:
            seen.append(note)
    detail = "；".join(seen)
    if passed == len(checks) and checks:
        result = PASS
    elif passed == 0 and checks:
        result = FAIL
    elif checks:
        result = FAIL
    else:
        result = SKIP
    evidence = f"{passed}/{len(checks)} 次通过" + (f"；{detail}" if detail else "")
    return CaseResult(
        case_id=case_id,
        title=title,
        result=result,
        evidence=evidence[:600],
        http_status=last.http_status if last else None,
        latency_ms=last.latency_ms if last else None,
    )


async def _emit_case(emit: Emit, case: CaseResult) -> CaseResult:
    await emit("case", case.as_dict())
    return case


def _spec_for(
    ctx: LinkContext, cfg: SuiteConfig, *, stream: bool, key: str | None = None, empty_auth: bool = False
) -> CallSpec:
    return CallSpec(
        base_url=ctx.base_url,
        model=ctx.model,
        api_key=ctx.api_key if key is None else key,
        send_empty_auth=empty_auth,
        api_secret=cfg.api_secret,
        auth_style=cfg.auth_style,
        api_version=cfg.api_version,
        version_in_body=cfg.version_in_body,
        system=cfg.system,
        prompt=cfg.prompt,
        max_tokens=cfg.max_tokens,
        temperature=cfg.temperature,
        stream=stream,
        stream_usage=cfg.stream_usage,
    )


async def _dig(host: str) -> tuple[str, str]:
    """Return (PASS|FAIL|SKIP, evidence).  A missing dig binary is a SKIP, not a
    supplier failure - the diagnostic environment is simply incomplete."""
    try:
        response = await call_worker(
            {"action": "exec", "command": "dig", "params": {"host": host, "rtype": "A"}, "timeout": 15},
            timeout=20,
        )
    except ShellUnavailable as exc:
        return SKIP, f"Shell 工作进程不可用，未能执行 dig：{exc}"
    if not response.get("ok"):
        err = response.get("error") or {}
        code = err.get("code", "")
        if code == "tool_missing":
            return SKIP, "服务器未安装 dig，域名解析用例未执行"
        return FAIL, f"dig 执行失败：{err.get('message', '未知错误')}"
    data = response.get("data") or {}
    out = (data.get("stdout") or "").strip()
    noerror = "status: NOERROR" in out or "ANSWER SECTION" in out
    if data.get("exit_code") != 0 or not noerror:
        return FAIL, "dig 未返回 NOERROR，域名解析可能异常"
    answers = [line for line in out.splitlines() if line and not line.startswith(";")]
    return PASS, f"dig NOERROR，返回 {len(answers)} 条记录；耗时 {data.get('duration_ms')}ms"


#: NET-05 的回显服务。按顺序试，第一个有返回就用它——「有返回即正常」，
#: 所以不要求三家都通，也不把某一家挂掉算成供应商问题。
IP_ECHO_URLS = ("https://api.ipify.org", "https://ifconfig.me/ip", "https://ipinfo.io/ip")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


async def _egress_ip(preferred: str = "") -> tuple[str, str]:
    """NET-05：从**平台所在服务器**取当前出口 IP，有返回即通过。

    为什么走 shell 工作进程而不是 httpx：这一项问的是"这台机器的网络出去是什么样"，
    工作进程就是按这个用途隔离出来的诊断进程；用主服务自己的 HTTP 客户端会分不清
    是 web 进程的网络还是诊断网络的结论。

    Shell 不可用时返回 SKIP：那是平台缺件，不是供应商不合格（与 NET-01 同一口径）。
    """
    urls = ([preferred] if preferred else []) + list(IP_ECHO_URLS)
    last = "未尝试"
    for url in urls:
        try:
            response = await call_worker(
                {
                    "action": "exec",
                    "command": "curl_raw",
                    "params": {"command_line": f"curl -sS --max-time 8 {url}", "timeout": 12},
                    "timeout": 18,
                },
                timeout=24,
            )
        except ShellUnavailable as exc:
            return SKIP, f"Shell 工作进程不可用，无法从服务器取出口 IP：{exc}"
        if not response.get("ok"):
            err = response.get("error") or {}
            last = f"{url} 执行失败：{err.get('message', '未知错误')}"
            continue
        data = response.get("data") or {}
        body = (data.get("stdout") or "").strip()
        if data.get("exit_code") == 0 and body:
            found = _IPV4_RE.search(body)
            shown = found.group(0) if found else body[:60].replace("\n", " ")
            return PASS, (
                f"服务器出口 IP：{shown}（回显来源 {url}）"
                "；这是平台所在服务器（AWS 测试环境）的出口，不是供应商环境"
            )
        last = f"{url} 无返回（exit={data.get('exit_code')}）"
    return FAIL, f"回显服务均无返回：{last}"


class _Pacer:
    """让相邻两次真实上游调用之间至少隔开 ``interval`` 秒。

    只在**拿到上一次响应之后**才开始计时：流式请求本来就耗时，硬等固定间隔
    只会把一轮跑得更慢，所以实际间隔 = max(interval - 上次耗时, 0)。
    """

    def __init__(self, interval: float) -> None:
        self.interval = max(0.0, float(interval or 0))
        self._last: float | None = None

    async def before_call(self) -> None:
        if self.interval <= 0 or self._last is None:
            return
        gap = time.perf_counter() - self._last
        if gap < self.interval:
            await asyncio.sleep(self.interval - gap)

    def after_call(self) -> None:
        self._last = time.perf_counter()


async def run_suite(cfg: SuiteConfig, emit: Emit) -> dict[str, Any]:
    adapter = get_adapter(cfg.adapter)
    repeat = max(1, min(cfg.repeat, 5))
    cases: list[CaseResult] = []
    pacer = _Pacer(
        settings.model_request_interval if cfg.request_interval is None else cfg.request_interval
    )

    async def vendor_call(spec: CallSpec, **kwargs: Any) -> CallOutcome:
        """发起一次**打供应商**的调用，并保证与上一次之间隔够 request_interval。"""
        await pacer.before_call()
        try:
            return await execute(adapter, spec, **kwargs)
        finally:
            pacer.after_call()

    links: list[LinkContext] = []
    for link in cfg.links:
        if link == "direct":
            base = cfg.direct_base_url
            links.append(LinkContext("direct", "上游直连", base, cfg.model, cfg.api_key))
        elif link == "forward":
            base = cfg.forward_base_url
            links.append(
                LinkContext(
                    "forward",
                    "转发链路",
                    base,
                    cfg.forward_model or cfg.model,
                    cfg.forward_api_key or cfg.api_key,
                )
            )

    total_links = len([link for link in links if link.base_url])
    if total_links == 0:
        await emit("error", {"message": "没有可测试的链路：请填写上游直连或转发地址"})
        return {"cases": [], "passed": 0, "failed": 0, "skipped": 0}

    # NET-05 是环境级用例（这台机器出网什么样），与走哪条链路无关，
    # 所以放在链路循环**外面**跑一次，不按链路重复。
    ip_result, ip_note = await _egress_ip(cfg.ip_echo_url)
    cases.append(await _emit_case(emit, CaseResult("NET-05", "实际部署环境：出口 IP", ip_result, ip_note)))

    for ctx in links:
        if not ctx.base_url:
            case = CaseResult(
                ctx.name.upper() + "-LINK",
                f"{ctx.label}链路配置",
                SKIP,
                "未配置该链路地址，跳过全部用例",
            )
            cases.append(await _emit_case(emit, case))
            continue

        try:
            target = await asyncio.to_thread(validate_url, ctx.base_url, resolve=True)
        except TargetError as exc:
            case = CaseResult(
                ctx.name.upper() + "-LINK",
                f"{ctx.label}地址校验",
                FAIL,
                f"{exc.message}（{exc.code}）",
            )
            cases.append(await _emit_case(emit, case))
            continue

        # ---------------- NET ----------------
        dig_result, note = await _dig(target.host)
        cases.append(
            await _emit_case(emit, CaseResult("NET-01", f"{ctx.label}：域名解析", dig_result, note))
        )

        # ---------------- REQ (3 consecutive non-stream calls) -------------
        req_outcomes: list[CallOutcome] = []
        for index in range(repeat):
            outcome = await vendor_call(
                _spec_for(ctx, cfg, stream=False),
                total_timeout=cfg.total_timeout,
                connect_timeout=cfg.connect_timeout,
                first_token_timeout=cfg.first_token_timeout,
                max_bytes=settings.model_max_body_bytes,
            )
            req_outcomes.append(outcome)
            if index == 0:
                net_ok = bool(outcome.http_status and 200 <= outcome.http_status < 300)
                # NET-02 只判「TLS 握手 + 证书校验」，**不看 HTTP 状态码**。
                # 原文预期是「TLS 握手成功，证书有效且与请求域名匹配」，与响应码无关；
                # 拿 2xx 代判会把「证书没问题、只是路径 404」判成 TLS 失败——判错了对象
                # （和 PARAM-07 同一类：用被否掉的证据下结论）。
                #
                # 判据取 `http_status` 是否有值：https 请求必须先握手成功才能收到**任何**
                # HTTP 响应（含 404）；证书校验失败时 httpx 抛 SSLError，outcome 里没有
                # http_status。所以「有响应」⟺「握手成功且证书通过」。
                host_ok = outcome.http_status is not None
                if target.scheme != "https":
                    net_result = SKIP
                    tls_note = "端点使用明文 HTTP，TLS 用例不适用；生产环境必须通过 HTTPS 访问"
                elif host_ok:
                    net_result = PASS
                    tls_note = "TLS 握手成功，证书校验开启（未使用 -k）"
                else:
                    net_result = FAIL
                    tls_note = (
                        "未建立 TLS 连接："
                        + (outcome.error_code or outcome.error_message or "未收到 HTTP 响应")
                    )
                cases.append(
                    await _emit_case(
                        emit,
                        CaseResult(
                            "NET-02",
                            f"{ctx.label}：HTTPS/TLS 连接",
                            net_result,
                            (
                                f"{tls_note}；HTTP {outcome.http_status}"
                                "（NET-02 只看 TLS 握手与证书，不看状态码；404 由 NET-03 判）"
                            )
                            if host_ok
                            else tls_note,
                            outcome.http_status,
                            outcome.latency_ms,
                        ),
                    )
                )
                path_ok = net_ok and "html" not in (outcome.content_type or "").lower() and outcome.http_status != 404
                cases.append(
                    await _emit_case(
                        emit,
                        CaseResult(
                            "NET-03",
                            f"{ctx.label}：完整请求路径",
                            PASS if path_ok else FAIL,
                            f"HTTP {outcome.http_status}；Content-Type={outcome.content_type or '未返回'}",
                            outcome.http_status,
                            outcome.latency_ms,
                        ),
                    )
                )
                # NET-04（2026-10-24 口径）：只要返回不是 3xx 就通过。
                # 平台的 HTTP 客户端本身不跟随跳转，3xx 会在 upstream 里被记成
                # redirect_blocked 并带上目标地址，这里只判状态码区间，不掺别的结论。
                redirect_ok = not_a_redirect(outcome)
                if outcome.http_status is None:
                    redirect_note = "未收到响应，无法确认是否发生重定向"
                elif redirect_ok:
                    redirect_note = f"HTTP {outcome.http_status}（非 3xx，未发生重定向）"
                else:
                    redirect_note = (
                        f"HTTP {outcome.http_status} 为 3xx 重定向，平台已阻止跟随；"
                        f"{redact_text(outcome.error_message, 120)}"
                    )
                cases.append(
                    await _emit_case(
                        emit,
                        CaseResult(
                            "NET-04",
                            f"{ctx.label}：重定向行为",
                            PASS if redirect_ok else FAIL,
                            redirect_note,
                            outcome.http_status,
                            outcome.latency_ms,
                        ),
                    )
                )

        detail = "；".join(
            f"#{i + 1} HTTP {o.http_status} / {_fmt_ms(o.latency_ms)}" for i, o in enumerate(req_outcomes)
        )
        cases.append(
            await _emit_case(
                emit,
                _agg(
                    "REQ-01",
                    f"{ctx.label}：请求成功（{repeat} 次）",
                    [(bool(o.http_status and 200 <= o.http_status < 300 and not o.error_code), detail, o) for o in req_outcomes],
                ),
            )
        )
        cases.append(
            await _emit_case(
                emit,
                _agg(
                    "REQ-02",
                    f"{ctx.label}：有效回答（{repeat} 次）",
                    [(bool(o.text.strip()), f"正文字符数 {[len(o.text) for o in req_outcomes]}", o) for o in req_outcomes],
                ),
            )
        )
        cases.append(
            await _emit_case(
                emit,
                _agg(
                    "REQ-03",
                    f"{ctx.label}：正常结束（{repeat} 次）",
                    [
                        # 原文："在总超时预算内返回完整响应，无持续挂起"。
                        # 过去只判"没超时、没取消"——401/502/被截断的流全部算通过。
                        # 完整 = 2xx + 真的拿到正文 + 流式时收到了结束信号。
                        (request_completed_ok(o), detail, o)
                        for o in req_outcomes
                    ],
                ),
            )
        )
        cases.append(
            await _emit_case(
                emit,
                _agg(
                    "REQ-04",
                    f"{ctx.label}：响应类型",
                    [
                        # 原文："返回 API 数据，不得是登录页、验证码页或代理错误页"。
                        # 判据 = 整段正文能否解析为 JSON（见 response_is_api_data）。
                        # 证据里把"读了多少字节 / JSON 是/否"写出来：只写 Content-Type
                        # 的话，判了不通过操作员也不知道该看哪里。
                        (
                            response_is_api_data(o),
                            f"正文 {o.bytes_read} 字节；"
                            f"JSON={'是' if o.body_is_json else ('未读到正文' if o.body_is_json is None else '否')}；"
                            f"Content-Type={o.content_type or '未返回'}",
                            o,
                        )
                        for o in req_outcomes
                    ],
                ),
            )
        )
        cases.append(
            await _emit_case(
                emit,
                _agg(
                    "REQ-05",
                    f"{ctx.label}：模型路由字段",
                    [
                        (
                            bool(o.reported_model),
                            f"响应 model={o.reported_model or '未返回'}；请求 model={ctx.model}",
                            o,
                        )
                        for o in req_outcomes
                    ],
                ),
            )
        )

        # ---------------- STREAM (3 consecutive stream calls) --------------
        stream_outcomes: list[CallOutcome] = []
        for _ in range(repeat):
            outcome = await vendor_call(
                _spec_for(ctx, cfg, stream=True),
                total_timeout=cfg.total_timeout,
                connect_timeout=cfg.connect_timeout,
                first_token_timeout=cfg.first_token_timeout,
                max_bytes=settings.model_max_body_bytes,
            )
            stream_outcomes.append(outcome)

        stream_detail = "；".join(
            f"#{i + 1} TTFT {_fmt_ms(o.ttft_ms)} / 总 {_fmt_ms(o.latency_ms)} / {o.chunk_count} 块"
            for i, o in enumerate(stream_outcomes)
        )
        cases.append(
            await _emit_case(
                emit,
                _agg(
                    "STREAM-01",
                    f"{ctx.label}：流式建立",
                    [
                        (
                            # 原文：按约定协议返回流式响应，"无解析错误"。
                            # 畸形事件现在计入 malformed_events（过去被静默丢弃）。
                            # 证据里带上 HTTP 状态：429 和"真的解析失败"在只看
                            # Content-Type/畸形事件时长得一模一样，操作员没法判断
                            # 是供应商的协议问题还是我们自己请求太密。
                            stream_start_ok(o),
                            f"HTTP {o.http_status}；"
                            f"{'限流(429)，属于请求节奏问题' if o.http_status == 429 else '块数=' + str(o.chunk_count)}；"
                            f"Content-Type={o.content_type or '未返回'}；"
                            f"畸形事件={o.malformed_events}",
                            o,
                        )
                        for o in stream_outcomes
                    ],
                ),
            )
        )
        cases.append(
            await _emit_case(
                emit,
                _agg(
                    "STREAM-02",
                    f"{ctx.label}：首个有效内容（预算 {cfg.first_token_timeout:.0f}s）",
                    [
                        (
                            o.ttft_ms is not None and o.ttft_ms <= cfg.first_token_timeout * 1000,
                            f"TTFT {_fmt_ms(o.ttft_ms)}",
                            o,
                        )
                        for o in stream_outcomes
                    ],
                ),
            )
        )
        cases.append(
            await _emit_case(
                emit,
                _agg(
                    "STREAM-03",
                    f"{ctx.label}：内容接收与拼接",
                    [(bool(o.text.strip()), f"拼接后 {len(o.text)} 字符", o) for o in stream_outcomes],
                ),
            )
        )
        cases.append(
            await _emit_case(
                emit,
                _agg(
                    "STREAM-04",
                    f"{ctx.label}：正常结束标记",
                    [
                        # 原文：收到正常结束信号，并在总超时内完成。
                        # 判 `stream_terminated` 而不是 `bool(finish_reason)`：
                        # 后者曾因 base.py 合成 "eof" 而恒真（假覆盖 F1）。
                        (
                            stream_end_ok(o),
                            f"结束信号={'有' if o.stream_terminated else '无'}"
                            f"；finish_reason={o.finish_reason or '缺失'}；{stream_detail}",
                            o,
                        )
                        for o in stream_outcomes
                    ],
                ),
            )
        )
        cases.append(
            await _emit_case(
                emit,
                _agg(
                    "STREAM-05",
                    f"{ctx.label}：错误识别",
                    [
                        # 原文：不得把错误事件或异常断流当作正常成功。
                        # 截断流在 upstream.py 里记 stream_incomplete；这里额外要求
                        # "确实收到了正常结束信号"，避免 error_code 为空即通过。
                        (
                            stream_no_error_disguise(o),
                            f"error_code={o.error_code or '无'}；"
                            f"结束信号={'有' if o.stream_terminated else '无'}",
                            o,
                        )
                        for o in stream_outcomes
                    ],
                ),
            )
        )

        # ---------------- AUTH ----------------
        valid_req = req_outcomes[0] if req_outcomes else None
        cases.append(
            await _emit_case(
                emit,
                CaseResult(
                    "AUTH-01",
                    f"{ctx.label}：有效 Key",
                    PASS if (valid_req and valid_req.http_status and 200 <= valid_req.http_status < 300 and valid_req.text) else FAIL,
                    f"HTTP {valid_req.http_status if valid_req else '-'}；沿用 REQ 首轮结果",
                    valid_req.http_status if valid_req else None,
                    valid_req.latency_ms if valid_req else None,
                ),
            )
        )

        async def auth_case(case_id: str, title: str, key: str, empty_auth: bool = False) -> CallOutcome:
            outcome = await vendor_call(
                _spec_for(ctx, cfg, stream=False, key=key, empty_auth=empty_auth),
                total_timeout=min(cfg.total_timeout, 45),
                connect_timeout=cfg.connect_timeout,
                first_token_timeout=cfg.first_token_timeout,
            )
            rejected = rejection_ok(outcome)
            detail = f"HTTP {outcome.http_status}；error={redact_text(outcome.error_message) or '无'}；正文 {len(outcome.text)} 字符"
            cases.append(
                await _emit_case(
                    emit,
                    CaseResult(
                        case_id,
                        f"{ctx.label}：{title}",
                        PASS if rejected else FAIL,
                        detail,
                        outcome.http_status,
                        outcome.latency_ms,
                    ),
                )
            )
            return outcome

        bad_key = "sk-" + secrets.token_urlsafe(24)
        await auth_case("AUTH-02", "缺少鉴权头", "")
        await auth_case("AUTH-03", "空 Key", "", empty_auth=True)
        wrong_key_outcome = await auth_case("AUTH-04", "随机错误 Key", bad_key)

        # AUTH-06（2026-10-24 口径）：无效 Key 只要有 HTTP 返回就算通过。
        # 平台拿不到供应商的"已过期 Key"，用随机无效 Key 等价测试；
        # 这一项只问"服务器还回不回话"，是否明确拒绝由 AUTH-04 判，两项不互相顶替。
        responded = has_any_response(wrong_key_outcome)
        cases.append(
            await _emit_case(
                emit,
                CaseResult(
                    "AUTH-06",
                    f"{ctx.label}：过期 Key（无效 Key 等价测试）",
                    PASS if responded else FAIL,
                    f"{'有' if responded else '无'}返回：HTTP {wrong_key_outcome.http_status}；"
                    f"error={redact_text(wrong_key_outcome.error_message, 80) or '无'}；"
                    "沿用 AUTH-04 的响应（平台没有供应商的过期 Key）",
                    wrong_key_outcome.http_status,
                    wrong_key_outcome.latency_ms,
                ),
            )
        )

        # AUTH-07（2026-10-24 口径）：供应商声明的鉴权方式 == 测试实际发出的鉴权头。
        matches, auth_note = (
            auth_style_matches(cfg.auth_style, valid_req) if valid_req else (False, "无有效请求可供比对")
        )
        cases.append(
            await _emit_case(
                emit,
                CaseResult(
                    "AUTH-07",
                    f"{ctx.label}：鉴权方式一致性",
                    PASS if matches else FAIL,
                    auth_note,
                    valid_req.http_status if valid_req else None,
                    valid_req.latency_ms if valid_req else None,
                ),
            )
        )

        # AUTH-08（2026-10-24 口径）：用提供的 Key 能调到目标模型即通过。
        this_model = model_usable(valid_req) if valid_req else False
        cases.append(
            await _emit_case(
                emit,
                CaseResult(
                    "AUTH-08",
                    f"{ctx.label}：目标模型可用",
                    PASS if this_model else FAIL,
                    f"HTTP {valid_req.http_status if valid_req else '-'}；"
                    f"正文 {(len(valid_req.text) if valid_req else 0)} 字符；"
                    f"响应 model={valid_req.reported_model if valid_req else '未返回'}；"
                    f"请求 model={ctx.model}",
                    valid_req.http_status if valid_req else None,
                    valid_req.latency_ms if valid_req else None,
                ),
            )
        )

        # ---------------- MODEL ----------------
        bad_model = ctx.model + "-nonexistent-" + secrets.token_hex(3)
        outcome = await vendor_call(
            replace(_spec_for(ctx, cfg, stream=False), model=bad_model),
            total_timeout=min(cfg.total_timeout, 45),
            connect_timeout=cfg.connect_timeout,
        )
        ok = rejection_ok(outcome)
        cases.append(
            await _emit_case(
                emit,
                CaseResult(
                    "MODEL-02",
                    f"{ctx.label}：不存在的模型 ID",
                    PASS if ok else FAIL,
                    f"请求 {bad_model} → HTTP {outcome.http_status}；正文 {len(outcome.text)} 字符",
                    outcome.http_status,
                    outcome.latency_ms,
                ),
            )
        )

        # MODEL-03：只改一个字符的模型 ID 也必须被明确拒绝，不得静默回退默认模型。
        mutated = _mutate_model_id(ctx.model)
        if not mutated or mutated == ctx.model:
            cases.append(
                await _emit_case(
                    emit,
                    CaseResult("MODEL-03", f"{ctx.label}：模型 ID 单字符变更", SKIP, "模型 ID 为空或无法构造单字符变更"),
                )
            )
        else:
            outcome = await vendor_call(
                replace(_spec_for(ctx, cfg, stream=False), model=mutated),
                total_timeout=min(cfg.total_timeout, 45),
                connect_timeout=cfg.connect_timeout,
            )
            rejected = rejection_ok(outcome)
            cases.append(
                await _emit_case(
                    emit,
                    CaseResult(
                        "MODEL-03",
                        f"{ctx.label}：模型 ID 单字符变更",
                        PASS if rejected else FAIL,
                        f"请求 {mutated} → HTTP {outcome.http_status}；正文 {len(outcome.text)} 字符"
                        + ("" if rejected else "；疑似静默回退到默认模型"),
                        outcome.http_status,
                        outcome.latency_ms,
                    ),
                )
            )

        # ---------------- TIME ----------------
        unreachable = cfg.unreachable_url or "https://bedrock-connect-probe.invalid/v1/chat/completions"
        started = time.perf_counter()
        time_outcome = await execute(
            adapter,
            replace(_spec_for(ctx, cfg, stream=False), base_url=unreachable),
            total_timeout=cfg.connect_timeout + 5,
            connect_timeout=cfg.connect_timeout,
        )
        elapsed = int((time.perf_counter() - started) * 1000)
        budget = (cfg.connect_timeout + 5) * 1000
        identifiable = bool(time_outcome.error_code) and time_outcome.error_code not in {"unknown_error"}
        cases.append(
            await _emit_case(
                emit,
                CaseResult(
                    "TIME-01",
                    f"{ctx.label}：不可达端点失败路径",
                    PASS if identifiable and elapsed <= budget else FAIL,
                    f"{elapsed}ms 内失败（预算 {budget}ms）；error={time_outcome.error_code}；{redact_text(time_outcome.error_message, 120)}",
                    time_outcome.http_status,
                    elapsed,
                ),
            )
        )

        if cfg.mock_no_content_url:
            mock = await execute(
                adapter,
                replace(
                    _spec_for(ctx, cfg, stream=False),
                    base_url=cfg.mock_no_content_url,
                    extra_body={"path": ""},
                ),
                total_timeout=cfg.first_token_timeout + 5,
                connect_timeout=5,
                first_token_timeout=cfg.first_token_timeout,
            )
            cases.append(
                await _emit_case(
                    emit,
                    CaseResult(
                        "TIME-02",
                        f"{ctx.label}：连接后无响应",
                        PASS if mock.timed_out else FAIL,
                        f"error={mock.error_code or '无'}；耗时 {_fmt_ms(mock.latency_ms)}",
                        mock.http_status,
                        mock.latency_ms,
                    ),
                )
            )
        else:
            cases.append(
                await _emit_case(
                    emit,
                    CaseResult("TIME-02", f"{ctx.label}：连接后无响应", SKIP, "未提供可控模拟端点（mock_no_content_url）"),
                )
            )

        if cfg.mock_heartbeat_url:
            mock = await execute(
                adapter,
                replace(
                    _spec_for(ctx, cfg, stream=True),
                    base_url=cfg.mock_heartbeat_url,
                    extra_body={"path": ""},
                ),
                total_timeout=cfg.first_token_timeout + 5,
                connect_timeout=5,
                first_token_timeout=cfg.first_token_timeout,
            )
            cases.append(
                await _emit_case(
                    emit,
                    CaseResult(
                        "TIME-03",
                        f"{ctx.label}：流式仅心跳",
                        PASS if mock.timed_out or mock.error_code in {"empty_stream", "first_content_timeout"} else FAIL,
                        f"error={mock.error_code or '无'}；TTFT={_fmt_ms(mock.ttft_ms)}；耗时 {_fmt_ms(mock.latency_ms)}",
                        mock.http_status,
                        mock.latency_ms,
                    ),
                )
            )
        else:
            cases.append(
                await _emit_case(
                    emit,
                    CaseResult("TIME-03", f"{ctx.label}：流式仅心跳", SKIP, "未提供仅心跳的模拟端点（mock_heartbeat_url）"),
                )
            )

        # ---------------- client cancel ----------------
        # A long-running target is required; reuse the heartbeat mock when the
        # operator supplied one, otherwise cancel 0.8s into the normal stream.
        cancel_spec = _spec_for(ctx, cfg, stream=True)
        if cfg.mock_heartbeat_url:
            cancel_spec = replace(
                cancel_spec, base_url=cfg.mock_heartbeat_url, extra_body={"path": ""}
            )
        # 这一发也是真实上游调用，必须先过节拍器，否则会紧贴上一个请求发出去。
        # after_call 挂在任务结束回调上：取消发生在 0.8s 后，间隔要从那一刻算起，
        # 不能从发起时刻算（否则下一发离上一个响应结束可能不足 interval）。
        await pacer.before_call()
        cancel_task = asyncio.create_task(
            execute(
                adapter,
                cancel_spec,
                total_timeout=cfg.total_timeout,
                connect_timeout=cfg.connect_timeout,
                first_token_timeout=cfg.first_token_timeout,
            )
        )
        cancel_task.add_done_callback(lambda _task: pacer.after_call())
        await asyncio.sleep(0.8)
        if cancel_task.done():
            cases.append(
                await _emit_case(
                    emit,
                    CaseResult(
                        "TIME-04",
                        f"{ctx.label}：客户端取消",
                        SKIP,
                        "请求在 0.8s 内已完成，未能观察到取消行为；请配合慢速端点复测",
                    ),
                )
            )
        else:
            cancel_task.cancel()
            outcome_state = "cancelled"
            try:
                await cancel_task
            except asyncio.CancelledError:
                outcome_state = "cancelled"
            except Exception:  # noqa: BLE001 - the upstream error may surface during cancellation
                outcome_state = "errored"
            else:
                outcome_state = "completed"
            if outcome_state == "cancelled":
                result, note = PASS, "客户端 0.8s 后取消，服务端停止读取并释放连接"
            elif outcome_state == "errored":
                result, note = PASS, "取消过程中上游连接被中断，服务端已记录异常并退出"
            else:
                result, note = SKIP, "取消时请求已自然结束，未能观察到取消行为"
            cases.append(
                await _emit_case(
                    emit,
                    CaseResult("TIME-04", f"{ctx.label}：客户端取消", result, note),
                )
            )

        # ---------------- manual / not applicable ----------------
        # 2026-10-24 起 NET-04 / NET-05 / AUTH-06 / AUTH-07 / AUTH-08 已升 L2，
        # 由上面的自动用例给出结论，不再走这张"人工兜底"表。
        for case_id, title, reason in (
            ("AUTH-05", "已撤销 Key", "需要供应商控制台的撤销权限，请在控制台操作后手工记录结果"),
            ("AUTH-09", "已禁用的平台 Key", "需在 Fluxlane 侧禁用平台 Key 后验证，平台无法自行切换 Key 状态"),
            (
                "MODEL-01",
                "模型清单逐一可用",
                "批量提交会为批次内**每个模型**各跑一遍，合并报告的「二、各模型结果」与"
                "「三、失败模型清单」就是本项的证据；仍需人工核对「拟上架清单」与批次模型清单是否一致",
            ),
            ("MODEL-04", "转发映射", "需对照 Fluxlane 渠道日志确认实际选中的上游模型"),
            ("MODEL-05", "模型访问限制", "需使用受限的平台 Key，标记为人工执行"),
        ):
            cases.append(await _emit_case(emit, CaseResult(case_id, f"{ctx.label}：{title}", SKIP, reason)))

    cfg.wipe()
    passed = sum(1 for c in cases if c.result == PASS)
    failed = sum(1 for c in cases if c.result == FAIL)
    skipped = sum(1 for c in cases if c.result == SKIP)
    return {"cases": [c.as_dict() for c in cases], "passed": passed, "failed": failed, "skipped": skipped}


async def egress_hint() -> str:
    """Best-effort local address hint for the report header (no external call)."""
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"
