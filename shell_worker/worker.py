"""Sandboxed network diagnostics worker.

This process is deliberately separate from the web application:

  * it runs as an unprivileged account (``bedrock-shell``), never as root;
  * it only knows three programs (curl / ping / dig) and never touches a shell;
  * it re-validates every argument even though the web tier already did;
  * it refuses private, loopback, link-local and cloud-metadata targets unless
    the operator explicitly enabled them in its *own* environment file;
  * each child process gets a minimal environment, so database passwords, AK/SK
    and session secrets from the service manager never reach it.

Transport is a newline-delimited JSON RPC over a unix socket (0660, owner =
this account, group = ``bedrock``) or, for Windows development only,
127.0.0.1 with an HMAC-signed payload.

The socket permissions are not merely attempted: after publishing they are
verified, and a mismatch is a startup failure.  A worker that is listening on
a socket the web tier cannot connect to must never look healthy.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import stat
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

try:  # 以包方式运行时（systemd / 测试）走相对导入
    from . import curl_options
except ImportError:  # pragma: no cover - 直接 python worker.py 调试时
    import curl_options  # type: ignore[no-redef]

WORKER_VERSION = "1.0.0"
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_\-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_\-]{1,63}(?<!-))*\.?$")
ALLOWED_RTYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"}
METADATA_IPS = {
    "169.254.169.254",
    "169.254.170.2",
    "169.254.169.253",
    "100.100.100.200",
    "fd00:ec2::254",
}


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass
class WorkerConfig:
    socket_path: str = os.environ.get("SHELL_SOCKET", "")
    host: str = os.environ.get("SHELL_HOST", "127.0.0.1")
    port: int = env_int("SHELL_PORT", 9700)
    token: str = os.environ.get("SHELL_TOKEN", "")
    allow_private: bool = env_bool("SHELL_ALLOW_PRIVATE", False)
    extra_hosts: tuple[str, ...] = tuple(
        h.strip().lower() for h in os.environ.get("SHELL_EXTRA_HOSTS", "").split(",") if h.strip()
    )
    allowed_ports: set[int] = field(default_factory=lambda: {
        int(p) for p in os.environ.get("SHELL_ALLOWED_PORTS", "80,443,8080,8443").split(",") if p.strip().isdigit()
    })
    max_concurrency: int = env_int("SHELL_MAX_CONCURRENCY", 4)
    output_limit: int = env_int("SHELL_OUTPUT_LIMIT", 65536)
    timeout_max: int = env_int("SHELL_TIMEOUT_MAX", 30)
    connect_timeout_max: int = env_int("SHELL_CONNECT_TIMEOUT_MAX", 10)
    # -L/--location 允许跟随重定向，但次数由平台钳制：0 = 不允许跟随（严格模式）。
    # 重定向目标不经过 --resolve 固定，严格环境把它设为 0。
    max_redirs: int = env_int("SHELL_MAX_REDIRS", 5)
    allow_root: bool = env_bool("SHELL_ALLOW_ROOT", False)
    curl_path: str = os.environ.get("SHELL_CURL_PATH", "") or (shutil.which("curl") or "/usr/bin/curl")
    ping_path: str = os.environ.get("SHELL_PING_PATH", "") or (shutil.which("ping") or "/bin/ping")
    dig_path: str = os.environ.get("SHELL_DIG_PATH", "") or (shutil.which("dig") or "/usr/bin/dig")


CFG = WorkerConfig()
SEMAPHORE = asyncio.Semaphore(max(1, CFG.max_concurrency))
STARTED = time.time()
IS_WIN = sys.platform.startswith("win")


def child_env() -> dict[str, str]:
    """Minimal environment for the child process.

    On Linux every service-manager variable (database password, AK/SK, session
    secret) is dropped.  Windows is supported for local development only; there
    the loader needs SystemRoot/PATH to start curl.exe at all.
    """
    if IS_WIN:
        return {
            "PATH": os.environ.get("PATH", ""),
            "SystemRoot": os.environ.get("SystemRoot", r"C://Windows"),
            "TEMP": tempfile.gettempdir(),
            "TMP": tempfile.gettempdir(),
            "PATHEXT": os.environ.get("PATHEXT", ".COM;.EXE;.BAT"),
        }
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
    }


class CommandError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def validate_host(raw: str) -> str:
    host = (raw or "").strip()
    if not host:
        raise CommandError("invalid_host", "目标主机不能为空")
    if len(host) > 253:
        raise CommandError("invalid_host", "目标主机过长")
    if any(ch in host for ch in "\r\n\t /\\@\"'`$;&|<>()"):
        raise CommandError("invalid_host", "目标主机包含非法字符")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not HOST_RE.match(host):
        raise CommandError("invalid_host", "目标主机不是合法的域名或 IP 地址")
    return host.rstrip(".")


def resolve(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise CommandError("dns_failed", f"域名解析失败: {exc.strerror or exc}") from exc
    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    if not ips:
        raise CommandError("dns_failed", "域名未解析到任何地址")
    return ips


def check_ip(addr: str) -> None:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        raise CommandError("invalid_host", f"无法识别的地址 {addr}") from None
    if str(ip) in METADATA_IPS:
        raise CommandError("blocked_target", "禁止访问云平台元数据地址")
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        raise CommandError("blocked_target", f"禁止访问保留地址 {ip}")
    if not CFG.allow_private:
        if ip.is_loopback:
            raise CommandError("blocked_target", "禁止访问本机回环地址")
        if ip.is_link_local:
            raise CommandError("blocked_target", "禁止访问链路本地地址")
        if ip.is_private:
            raise CommandError("blocked_target", "禁止访问内网地址")


def validate_target(host: str, port: int | None = None) -> tuple[str, list[str]]:
    host = validate_host(host)
    host_l = host.lower()
    if host_l == "localhost" and not CFG.allow_private and host_l not in CFG.extra_hosts:
        raise CommandError("blocked_target", "禁止访问 localhost")
    try:
        literal = ipaddress.ip_address(host)
        check_ip(str(literal))
        return host, [str(literal)]
    except ValueError:
        pass
    ips = resolve(host, port or 0)
    for addr in ips:
        check_ip(addr)
    return host, ips


def validate_url(raw: str) -> tuple[str, str, int, str]:
    url = (raw or "").strip()
    if not url:
        raise CommandError("invalid_url", "URL 不能为空")
    if len(url) > 2048:
        raise CommandError("invalid_url", "URL 过长")
    if any(ch in url for ch in "\r\n\t \"'`$|;&<>"):
        raise CommandError("invalid_url", "URL 包含非法字符")
    parts = urlsplit(url)
    if parts.scheme.lower() not in {"http", "https"}:
        raise CommandError("invalid_scheme", "仅支持 http/https")
    if parts.username or parts.password:
        raise CommandError("url_credentials", "URL 中不允许包含认证信息")
    if parts.fragment:
        raise CommandError("invalid_url", "URL 不允许包含片段")
    host = validate_host(parts.hostname or "")
    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    if port not in CFG.allowed_ports:
        allowed = ",".join(str(p) for p in sorted(CFG.allowed_ports))
        raise CommandError("port_not_allowed", f"端口 {port} 未获授权，允许的端口: {allowed}")
    _, ips = validate_target(host, port)
    return parts.scheme.lower(), host, port, ips[0]


# ---------------------------------------------------------------------------
# command builders
# ---------------------------------------------------------------------------
def build_curl(params: dict) -> tuple[list[str], int]:
    url = str(params.get("url") or "")
    scheme, host, port, ip = validate_url(url)
    timeout = min(int(params.get("timeout") or 10), CFG.timeout_max)
    connect = min(int(params.get("connect_timeout") or 5), timeout, CFG.connect_timeout_max)
    method = "HEAD" if params.get("head_only") else "GET"
    argv = [
        CFG.curl_path,
        "--silent",
        "--show-error",
        "--no-progress-meter",
        "--proto", "=http,https",
        "--proto-redir", "=http,https",
        "--max-redirs", "0",
        "--connect-timeout", str(connect),
        "--max-time", str(timeout),
        "--max-filesize", "1048576",
        "--user-agent", "bedrock-netdiag/1.0",
        "--resolve", f"{host}:{port}:{ip}",
        "--dump-header", "-",
        "--output", "-",
        "--request", method,
        url,
    ]
    return argv, timeout + 5


def build_ping(params: dict) -> tuple[list[str], int]:
    host, ips = validate_target(str(params.get("host") or ""))
    count = max(1, min(int(params.get("count") or 3), 5))
    wait = max(1, min(int(params.get("timeout") or 3), 10))
    target = ips[0]
    argv = [CFG.ping_path, "-n", "-c", str(count), "-W", str(wait)]
    if ":" in target:
        argv.append("-6")
    argv.append(target)
    return argv, count * (wait + 1) + 3


def build_dig(params: dict) -> tuple[list[str], int]:
    host = validate_host(str(params.get("host") or ""))
    rtype = str(params.get("rtype") or "A").upper()
    if rtype not in ALLOWED_RTYPES:
        raise CommandError("invalid_type", f"不支持的记录类型，允许: {', '.join(sorted(ALLOWED_RTYPES))}")
    # dig performs its own lookup; still resolve first so blocked targets fail fast.
    validate_target(host)
    argv = [CFG.dig_path, host, rtype, "+time=3", "+tries=1", "+noall", "+answer", "+question", "+comments"]
    return argv, 12


BUILDERS = {"curl": build_curl, "ping": build_ping, "dig": build_dig}


# ---------------------------------------------------------------------------
# raw curl（自由命令模式）
# ---------------------------------------------------------------------------
# 放开的只是 curl 的“请求描述能力”，不是命令执行能力：
#   * 不经过 shell，argv 由 create_subprocess_exec 直接传给 curl；
#   * 只接受下面白名单内的参数，其余一律拒绝（-o/-K/@file/--resolve/代理等）；
#   * URL 仍走 validate_url（DNS 解析 + 私网/元数据拦截 + 端口白名单），
#     并用 --resolve 固定到已校验的 IP，避免 DNS rebinding；
#   * 禁止跟随重定向，避免 302 把请求带到未校验的地址。
RAW_CURL_DATA_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--json"}
RAW_CURL_FORM_FLAGS = {"-F", "--form"}
REDIRECT_MARK = "__BEDROCK_REDIRECT__"


def _expand_short(token: str) -> list[str]:
    """把合并/贴值的短参数还原成独立 token。

    ``-sSL`` → ``-s -S -L``；``-XPOST`` → ``-X POST``；``-m10`` → ``-m 10``；
    ``-d@f`` → ``-d @f``。curl 的这些写法在真实命令里到处都是，
    靠"逐字符都在白名单里"是判不出来的：``-X`` 是要吃值的。
    """
    body = token[1:]
    out: list[str] = []
    position = 0
    while position < len(body):
        char = body[position]
        long_name = curl_options.SHORT.get(char)
        if long_name is None:
            raise CommandError("option_not_allowed", f"curl 没有 -{char} 这个短参数（来自 {token}）")
        out.append(f"-{char}")
        if curl_options.LONG.get(long_name, 0):
            rest = body[position + 1 :]
            if rest:
                out.append(rest)
            position = len(body)
        else:
            position += 1
    return out



def _split_option(token: str) -> tuple[str, str | None]:
    """``--header=x`` / ``-H x`` / ``-Hx`` 三种写法归一为 (name, inline_value)。"""
    if token.startswith("--"):
        if "=" in token:
            name, _, value = token.partition("=")
            return name, value
        return token, None
    if len(token) > 2:
        return token[:2], token[2:]
    return token, None


def _positive_int(value: str, name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise CommandError("invalid_option", f"参数 {name} 需要整数") from None
    if number < 1:
        raise CommandError("invalid_option", f"参数 {name} 必须大于 0")
    return number


def _ensure_scheme(url: str) -> str:
    """补全省略的协议，与 curl 的行为一致。"""
    text = (url or "").strip()
    if "://" in text:
        return text
    if text.startswith("//"):
        return "http:" + text
    return "http://" + text


def parse_raw_curl(text: str, default_timeout: int) -> tuple[list[str], int, str]:
    """把一段 curl 命令解析成受控 argv。

    返回 ``(argv, hard_timeout, target_host)``。抛 ``CommandError`` 表示命令被拒绝，
    错误码会原样返回给前端（``option_not_allowed``、``file_read_blocked`` 等）。
    """
    raw = (text or "").strip()
    if not raw:
        raise CommandError("invalid_command", "请粘贴要执行的 curl 命令")
    if len(raw) > 8192:
        raise CommandError("invalid_command", "命令过长（上限 8192 字符）")

    # 支持反斜杠续行：curl 命令常从文档里多行复制。
    raw = raw.replace("\\\r\n", " ").replace("\\\n", " ")
    try:
        tokens = shlex.split(raw, posix=True)
    except ValueError as exc:
        raise CommandError("invalid_syntax", f"命令引号不匹配或无法解析：{exc}") from None
    if not tokens:
        raise CommandError("invalid_command", "请粘贴要执行的 curl 命令")
    if tokens[0].lower() in {"curl", "curl.exe"}:
        tokens = tokens[1:]

    urls: list[str] = []
    passthrough: list[str] = []
    max_time: int | None = None
    connect_timeout: int | None = None
    follow = False
    write_out_slot: int | None = None

    index = 0
    while index < len(tokens):
        token = tokens[index]
        # 合并短参数 / 贴值短参数：-sSL、-XPOST、-m10、-d@file 统一展开
        if token.startswith("-") and not token.startswith("--") and len(token) > 2:
            tokens[index : index + 1] = _expand_short(token)
            token = tokens[index]
        if token == "--":
            raise CommandError("option_not_allowed", "不支持 -- 分隔符")
        if token.startswith("-") and token != "-":
            name, inline = _split_option(token)
            # 表里只有长名，短参数先翻译成长名再查；回填 argv 时用用户原来的写法。
            key = name
            if not name.startswith("--"):
                long_name = curl_options.SHORT.get(name[1:]) if len(name) == 2 else None
                if long_name is None:
                    raise CommandError(
                        "option_not_allowed", f"curl 没有 {name} 这个短参数（来自 {token}）"
                    )
                key = long_name
            # --no-foo 是 curl 的布尔取反写法，按 --foo 的元数据判定
            if key.startswith("--no-") and key not in curl_options.LONG:
                positive = "--" + key[5:]
                if curl_options.LONG.get(positive) == 0:
                    key = positive
            if key not in curl_options.LONG:
                raise CommandError(
                    "option_not_allowed",
                    f"平台不认识参数 {name}。可用 curl --help all 核对拼写；"
                    "参数总表随 curl 8.x 全量收录，仍报这个错说明是 curl 新增参数，请升级平台",
                )
            reason = curl_options.blocked_reason(key)
            if reason:
                raise CommandError("option_not_allowed", reason)

            if not curl_options.LONG[key]:
                if inline is not None:
                    raise CommandError("option_not_allowed", f"参数 {name} 不接受值")
                if key == "--location":
                    follow = True
                passthrough.append(name)
                index += 1
                continue

            if inline is None:
                index += 1
                if index >= len(tokens):
                    raise CommandError("invalid_syntax", f"参数 {name} 缺少值")
                value = tokens[index]
            else:
                value = inline

            if key in RAW_CURL_DATA_FLAGS and value.startswith("@"):
                raise CommandError("file_read_blocked", "不允许从服务器文件读取请求体（@file）")
            if key == "--data-urlencode" and "@" in value:
                raise CommandError("file_read_blocked", "不允许从服务器文件读取请求体（name@file）")
            if key in RAW_CURL_FORM_FLAGS and ("@" in value or "<" in value):
                # -F name=@/etc/passwd、-F name=</etc/passwd 都是读本机文件
                raise CommandError("file_read_blocked", "不允许用 -F 从服务器文件上传（@file / <file）")
            if key == "--write-out" and value.startswith("@"):
                raise CommandError("file_read_blocked", "不允许从服务器文件读取输出格式")
            if key == "--cookie" and "=" not in value:
                # curl 会把不含 = 的值当作 cookie 文件路径
                raise CommandError("file_read_blocked", "Cookie 必须写成 name=value，不能用文件")

            if key == "--max-time":
                max_time = _positive_int(value, name)
            elif key == "--connect-timeout":
                connect_timeout = _positive_int(value, name)
            elif key == "--url":
                urls.append(value)
            else:
                if key == "--write-out":
                    write_out_slot = len(passthrough) + 1
                passthrough.extend([name, value])
            index += 1
            continue

        urls.append(token)
        index += 1

    if follow and CFG.max_redirs <= 0:
        raise CommandError(
            "option_not_allowed",
            "服务端禁用了重定向跟随（SHELL_MAX_REDIRS=0），请去掉 -L/--location",
        )
    # 跟随重定向时追加一个只读探针：最终 URL 与跳转次数会写进结果，
    # 这样"--location 把请求带到了别的域名"是看得见的，而不是悄悄发生。
    if follow:
        marker = f"\n{REDIRECT_MARK} %{{url_effective}} %{{num_redirects}}"
        if write_out_slot is not None:
            passthrough[write_out_slot] = str(passthrough[write_out_slot]) + marker
        else:
            passthrough.extend(["-w", marker])

    if not urls:
        raise CommandError("invalid_url", "命令中没有 http/https URL")
    if len(urls) > 1:
        raise CommandError("invalid_url", "一次只能执行一个 URL")
    # curl 本身允许省略协议（curl baidu.com 等价于 http://baidu.com），
    # 这里保持一致；非 http/https 的协议仍会被 validate_url 拒绝。
    target_url = _ensure_scheme(urls[0])
    scheme, host, port, ip = validate_url(target_url)

    total = min(max_time or default_timeout, CFG.timeout_max)
    connect = min(connect_timeout or min(5, total), CFG.connect_timeout_max, total)

    # 安全参数一律放在用户参数**之后**：curl 对同名参数取最后一个，
    # 这样 --max-time / --proto / --max-redirs / --resolve 不可能被用户顶掉。
    argv = [
        CFG.curl_path,
        "--no-progress-meter",
        *passthrough,
        "--proto", "=http,https",
        "--proto-redir", "=http,https",
        "--max-redirs", str(CFG.max_redirs if follow else 0),
        "--connect-timeout", str(connect),
        "--max-time", str(total),
        "--max-filesize", "1048576",
        "--resolve", f"{host}:{port}:{ip}",
        "--output", "-",
        target_url,
    ]
    return argv, total + 5, host


def build_curl_raw(params: dict) -> tuple[list[str], int]:
    timeout = int(params.get("timeout") or 20)
    argv, hard_timeout, host = parse_raw_curl(str(params.get("command_line") or ""), timeout)
    # run_command 用它写审计的 target_host（command_line 里没有 url 字段）
    params["target_host"] = host
    # 跟随重定向时会注入 --write-out 探针，执行完要把这一行剥掉并单列成字段
    params["_redirect_probe"] = any(REDIRECT_MARK in str(arg) for arg in argv)
    return argv, hard_timeout


def extract_redirect_info(text: str) -> tuple[str, dict | None]:
    """剥掉 ``__BEDROCK_REDIRECT__`` 探针行，返回 ``(干净输出, 重定向信息)``。

    探针由 ``parse_raw_curl`` 在 ``-L`` 时追加，形如
    ``__BEDROCK_REDIRECT__ https://final/path 2``。
    单独成字段而不是混在 stdout 里，前端才能把它显示成"跳转到了别的主机"的提示。
    """
    position = text.rfind(REDIRECT_MARK)
    if position < 0:
        return text, None
    body_start = text.rfind("\n", 0, position)
    cleaned = text[: body_start] if body_start >= 0 else text[:position]
    tail = text[position + len(REDIRECT_MARK) :].strip()
    final_url, _, count = tail.rpartition(" ")
    try:
        redirects = int(count)
    except ValueError:
        return cleaned, None
    return cleaned, {"final_url": final_url.strip(), "redirects": redirects}


BUILDERS["curl_raw"] = build_curl_raw


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------
async def run_command(command: str, params: dict) -> dict:
    builder = BUILDERS.get(command)
    if builder is None:
        raise CommandError("command_not_allowed", "该命令未获授权")
    argv, hard_timeout = builder(params)

    started = time.perf_counter()
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=tempfile.gettempdir(),
        env=child_env(),
        start_new_session=not IS_WIN,
    )

    timed_out = False
    truncated = False
    stdout = bytearray()
    stderr = bytearray()

    async def pump(reader: asyncio.StreamReader, sink: bytearray) -> bool:
        nonlocal truncated
        while True:
            chunk = await reader.read(8192)
            if not chunk:
                return True
            if len(sink) < CFG.output_limit:
                sink.extend(chunk[: CFG.output_limit - len(sink)])
            if len(sink) + len(chunk) > CFG.output_limit:
                truncated = True

    tasks = [
        asyncio.create_task(pump(proc.stdout, stdout)),
        asyncio.create_task(pump(proc.stderr, stderr)),
    ]
    try:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=hard_timeout)
        await asyncio.wait_for(proc.wait(), timeout=2)
    except asyncio.TimeoutError:
        timed_out = True
        if IS_WIN:
            proc.kill()
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
        await proc.wait()
    finally:
        for task in tasks:
            task.cancel()

    duration_ms = int((time.perf_counter() - started) * 1000)
    out_text = ANSI_RE.sub("", stdout.decode("utf-8", "replace"))
    err_text = ANSI_RE.sub("", stderr.decode("utf-8", "replace"))
    redirect_info: dict | None = None
    if params.get("_redirect_probe"):
        out_text, redirect_info = extract_redirect_info(out_text)
    exit_code = proc.returncode if proc.returncode is not None else -1
    if timed_out:
        exit_code = 124

    target = ""
    if params.get("target_host"):
        target = str(params["target_host"])
    elif params.get("url"):
        target = urlsplit(str(params["url"])).hostname or ""
    elif params.get("host"):
        target = str(params["host"])

    result = {
        "status": "timeout" if timed_out else ("ok" if exit_code == 0 else "error"),
        "command": command,
        "argv_display": " ".join(argv[:1] + ["…"]),  # never echo arbitrary targets back
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout": out_text[: CFG.output_limit],
        "stderr": err_text[: CFG.output_limit],
        "truncated": truncated,
        "timed_out": timed_out,
        "timeout_seconds": hard_timeout,
        "target_host": target,
    }
    if redirect_info is not None:
        # 只在真的发生过跳转时返回，前端据此提示"请求被带到了别的主机"
        result["redirect_count"] = redirect_info["redirects"]
        result["redirect_final_url"] = redirect_info["final_url"]
        result["redirect_left_host"] = bool(
            redirect_info["redirects"]
            and (urlsplit(redirect_info["final_url"]).hostname or "") != target
        )
    return result


# ---------------------------------------------------------------------------
# RPC server
# ---------------------------------------------------------------------------
async def handle_request(raw: bytes) -> dict:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {"ok": False, "error": {"code": "bad_request", "message": "请求不是合法 JSON"}}

    token = str(payload.get("token") or "")
    if not CFG.token or not hmac.compare_digest(token, CFG.token):
        return {"ok": False, "error": {"code": "unauthorized", "message": "调用方未通过工作进程鉴权"}}

    action = payload.get("action")
    if action == "health":
        return {
            "ok": True,
            "data": {
                "version": WORKER_VERSION,
                "pid": os.getpid(),
                "uid": os.geteuid() if hasattr(os, "geteuid") else -1,
                "user": _current_user(),
                "uptime_seconds": int(time.time() - STARTED),
                "allow_private": CFG.allow_private,
                "allowed_ports": sorted(CFG.allowed_ports),
                "extra_hosts": list(CFG.extra_hosts),
                "max_concurrency": CFG.max_concurrency,
                "output_limit": CFG.output_limit,
                "timeout_max": CFG.timeout_max,
                "commands": {name: os.path.isfile(path) for name, path in (
                    ("curl", CFG.curl_path), ("ping", CFG.ping_path), ("dig", CFG.dig_path))},
            },
        }

    if action != "exec":
        return {"ok": False, "error": {"code": "bad_action", "message": "未知的请求类型"}}

    command = str(payload.get("command") or "")
    params = payload.get("params") or {}
    if not isinstance(params, dict):
        return {"ok": False, "error": {"code": "bad_params", "message": "参数格式错误"}}

    acquired = False
    try:
        await asyncio.wait_for(SEMAPHORE.acquire(), timeout=5)
        acquired = True
    except asyncio.TimeoutError:
        return {"ok": False, "error": {"code": "busy", "message": "诊断进程并发已满，请稍后重试"}}

    try:
        result = await run_command(command, params)
        return {"ok": True, "data": result}
    except CommandError as exc:
        return {"ok": False, "error": {"code": exc.code, "message": exc.message}}
    except FileNotFoundError:
        return {"ok": False, "error": {"code": "tool_missing", "message": "服务器缺少所需命令，请联系管理员"}}
    except OSError as exc:
        return {"ok": False, "error": {"code": "exec_failed", "message": f"命令启动失败: {exc}"}}
    finally:
        if acquired:
            SEMAPHORE.release()


def _current_user() -> str:
    try:
        import pwd  # type: ignore

        return pwd.getpwuid(os.geteuid()).pw_name  # type: ignore[attr-defined]
    except Exception:
        return os.environ.get("USERNAME", "unknown")


async def client_connected(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=60)
            except asyncio.TimeoutError:
                break
            if not line:
                break
            response = await handle_request(line)
            writer.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


SOCKET_MODE = 0o660
DEFAULT_SOCKET_GROUP = "bedrock"
#: 自检失败时的退出码，便于 systemd / 运维脚本区分"权限不对"与"配置缺失(2)/root(3)"
SOCKET_PERMISSION_EXIT_CODE = 4


def socket_group_name() -> str:
    """期望的 socket 属组名。

    `SHELL_SOCKET_GROUP` 未设置时取默认的 ``bedrock``；显式设为空串表示本机
    没有 web 服务组（例如开发机），此时跳过属组设置与属组校验——但启动时
    会打印一条 WARNING，跳过是显式的，不是静默的。
    """
    raw = os.environ.get("SHELL_SOCKET_GROUP")
    if raw is None:
        return DEFAULT_SOCKET_GROUP
    return raw.strip()


def _lookup_group(group_name: str) -> tuple[int | None, str]:
    """按名字查 gid，返回 ``(gid, 失败原因)``；成功时原因为空串。"""
    try:
        import grp  # type: ignore
    except ImportError:  # Windows 没有 unix 组
        return None, "当前平台没有 grp 模块（Windows 无 unix 组）"
    try:
        return grp.getgrnam(group_name).gr_gid, ""
    except KeyError:
        return None, f"属组 {group_name!r} 在本机不存在"


def _user_name(uid: int) -> str:
    try:
        import pwd  # type: ignore

        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def _group_name(gid: int) -> str:
    try:
        import grp  # type: ignore

        return grp.getgrgid(gid).gr_name
    except Exception:
        return str(gid)


def describe_socket_owner(path: Path) -> str:
    """``owner:group(mode)`` 的一行描述，用于启动日志与失败诊断。"""
    try:
        info = path.stat()
    except OSError as exc:
        return f"<stat 失败: {exc}>"
    return f"{_user_name(info.st_uid)}:{_group_name(info.st_gid)}({oct(info.st_mode & 0o777)})"


def _chgrp(path: Path) -> None:
    """把属组切成 web 服务所在组。

    仍然保持"尽力而为"（不抛异常），因为最终结果由启动自检
    :func:`enforce_socket_permissions` 做硬校验；但失败原因必须写到 stderr。
    过去这里是 ``except OSError: pass``，于是 chgrp 失败后 journalctl 里
    只剩一行看起来完全正常的 ``listening ... mode=0o660``，属组错无从发现。
    """
    group_name = socket_group_name()
    if not group_name:
        return
    gid, why = _lookup_group(group_name)
    if gid is None:
        print(
            f"[shell-worker] chgrp({path}) 跳过：{why}。"
            f"请创建该组（groupadd {group_name}）或设置 SHELL_SOCKET_GROUP。",
            file=sys.stderr,
            flush=True,
        )
        return
    try:
        os.chown(path, -1, gid)
    except OSError as exc:
        print(
            f"[shell-worker] chgrp({path}, {group_name}) 失败: {exc}。"
            "常见原因：进程缺少 CAP_CHOWN，且当前进程主组不是 "
            f"{group_name}（只有 unit 里 Group={group_name} 生效时才成立；"
            "手工启动或沿用同名遗留用户时不成立）。",
            file=sys.stderr,
            flush=True,
        )


def prepare_runtime_dir(parent: Path) -> None:
    """确保 socket 所在目录可被同组进程穿越。

    systemd 的 RuntimeDirectory=bedrock 已经建好 0770 目录；手工启动时
    目录会被 UMask=0077 建成 0700，主服务就进不来（EACCES）。
    只在目录属于当前用户时才改权限，避免误改 /run。
    """
    parent.mkdir(parents=True, exist_ok=True)
    try:
        info = parent.stat()
    except OSError as exc:
        print(f"[shell-worker] 无法 stat 运行目录 {parent}: {exc}", file=sys.stderr, flush=True)
        return
    if not hasattr(os, "geteuid") or info.st_uid != os.geteuid():
        # 不属于当前账号：不改（可能是 systemd 建好的、也可能是别人的 /run），
        # 但把"看起来正常其实不可穿越"的情况显式提示出来。
        if (info.st_mode & 0o070) != 0o070:
            print(
                f"[shell-worker] 运行目录 {parent} 属主不是当前账号且同组权限不足"
                f"（实际 {oct(info.st_mode & 0o777)}，期望同组 rwx），主服务可能无法穿越该目录。"
                "本进程无权修改，请用 systemd 的 RuntimeDirectoryMode 或手工修正。",
                file=sys.stderr,
                flush=True,
            )
        return
    try:
        os.chmod(parent, 0o770)
    except OSError as exc:
        print(
            f"[shell-worker] chmod({parent}, 0o770) 失败: {exc}；主服务可能无法穿越该目录。",
            file=sys.stderr,
            flush=True,
        )
    _chgrp(parent)


def publish_socket(path: Path) -> None:
    """把 unix socket 发布成 0660（属主 = 诊断进程，属组 = bedrock）。

    0600 会让主服务（另一个账号）在 connect 时直接 EACCES，页面表现为
    "无法连接 Shell 工作进程：[Errno 13] Permission denied"。
    这里的 chmod/chgrp 失败不再被吞掉：原因写 stderr，最终结果由
    :func:`enforce_socket_permissions` 硬校验。
    """
    try:
        os.chmod(path, SOCKET_MODE)
    except OSError as exc:
        print(
            f"[shell-worker] chmod({path}, {oct(SOCKET_MODE)}) 失败: {exc}；"
            "主服务（另一个账号）connect 时会 EACCES。",
            file=sys.stderr,
            flush=True,
        )
    _chgrp(path)


def check_socket_permissions(
    path: Path,
    expected_group: str | None = None,
    expected_gid: int | None = None,
) -> list[str]:
    """校验 socket 是不是 unix socket、权限位与属组是否为期望值。

    返回问题描述列表；空列表表示符合预期。``expected_group`` 为 ``None``
    时取 :func:`socket_group_name`（空串 = 只校验权限位，不校验属组）；
    ``expected_gid`` 显式给出时不再按名字解析属组（供测试注入）。
    """
    try:
        info = path.stat()
    except OSError as exc:
        return [f"无法读取 socket 状态 {path}: {exc}"]

    problems: list[str] = []
    if not stat.S_ISSOCK(info.st_mode):
        problems.append(f"{path} 不是 unix socket（st_mode={oct(info.st_mode)}）")

    mode = info.st_mode & 0o777
    if mode != SOCKET_MODE:
        problems.append(
            f"权限位不符：期望 {oct(SOCKET_MODE)}，实际 {oct(mode)}。"
            "主服务是另一个账号，非 0660 时 connect 会 EACCES。"
        )

    group_name = socket_group_name() if expected_group is None else expected_group
    if expected_gid is None and group_name:
        gid, why = _lookup_group(group_name)
        if gid is None:
            problems.append(f"无法校验属组：{why}。")
        else:
            expected_gid = gid
    if expected_gid is not None and info.st_gid != expected_gid:
        problems.append(
            f"属组不符：期望 {group_name or expected_gid}(gid={expected_gid})，"
            f"实际 {_group_name(info.st_gid)}(gid={info.st_gid})。"
            "属组错误时主服务 connect 会立即 EACCES。"
        )
    return problems


def enforce_socket_permissions(path: Path, expected_group: str | None = None) -> None:
    """自检不通过就打印诊断并以非 0 退出码退出，让 systemd 标 failed。

    宁可服务起不来，也不要"看起来在跑、实际全废"。
    """
    problems = check_socket_permissions(path, expected_group=expected_group)
    if not problems:
        return
    group_name = socket_group_name() if expected_group is None else expected_group
    try:
        mode = oct(path.stat().st_mode & 0o777)
    except OSError:
        mode = "?"
    print(
        "[shell-worker] socket 权限自检失败，拒绝继续提供服务"
        f"（退出码 {SOCKET_PERMISSION_EXIT_CODE}）：",
        file=sys.stderr,
        flush=True,
    )
    print(f"  socket : {path}", file=sys.stderr, flush=True)
    print(
        f"  期望   : owner={_current_user()} group={group_name or '(未校验)'} mode={oct(SOCKET_MODE)}",
        file=sys.stderr,
        flush=True,
    )
    print(
        f"  实际   : owner={_user_name(_safe_uid(path))} "
        f"group={_group_name(_safe_gid(path))} mode={mode}",
        file=sys.stderr,
        flush=True,
    )
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr, flush=True)
    print(
        "可能原因：\n"
        "  1) 进程主组不是目标属组（unit 里 Group= 未生效、手工启动、或沿用同名遗留用户），"
        "且没有 CAP_CHOWN 可以 chgrp；\n"
        "  2) 运行目录被别的 umask 建成 0700，主服务无法穿越；\n"
        "  3) SHELL_SOCKET_GROUP 指向了本机不存在的组。\n"
        "手工核对：stat -c '%U %G %a' <socket>；"
        "手工修复：sudo chgrp <group> <socket> && sudo chmod 0660 <socket>",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(SOCKET_PERMISSION_EXIT_CODE)


def _safe_uid(path: Path) -> int:
    try:
        return path.stat().st_uid
    except OSError:
        return -1


def _safe_gid(path: Path) -> int:
    try:
        return path.stat().st_gid
    except OSError:
        return -1


async def main() -> None:
    if not CFG.token:
        print("SHELL_TOKEN 未配置，拒绝启动", file=sys.stderr)
        raise SystemExit(2)
    if hasattr(os, "geteuid") and os.geteuid() == 0 and not CFG.allow_root:
        print("拒绝以 root 身份运行。请使用专用低权限账号（bedrock-shell）。", file=sys.stderr)
        raise SystemExit(3)

    if CFG.socket_path and not sys.platform.startswith("win"):
        path = Path(CFG.socket_path)
        prepare_runtime_dir(path.parent)
        if path.exists():
            path.unlink()
        server = await asyncio.start_unix_server(client_connected, path=str(path))
        publish_socket(path)
        expected_group = socket_group_name()
        if not expected_group:
            print(
                "[shell-worker] 警告：SHELL_SOCKET_GROUP 为空，已跳过 socket 属组设置与校验；"
                "主服务若不在同一账号下将因属组不符而 EACCES。",
                file=sys.stderr,
                flush=True,
            )
        try:
            enforce_socket_permissions(path)
        except SystemExit:
            server.close()
            await server.wait_closed()
            raise
        print(
            f"shell worker listening on unix:{path} {describe_socket_owner(path)} "
            f"期望属组={expected_group or '-'} uid={_current_user()}",
            flush=True,
        )
    else:
        server = await asyncio.start_server(client_connected, CFG.host, CFG.port)
        print(f"shell worker listening on tcp://{CFG.host}:{CFG.port} uid={_current_user()}", flush=True)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
