"""SSRF guard for operator-supplied endpoints.

Every outbound target is parsed, normalised, resolved and checked against a
block list before a socket is opened.  Redirects are never followed
automatically, so a public endpoint cannot bounce the request (and its
credentials) to an internal address.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import settings

# Cloud metadata endpoints must never be reachable, even when private targets
# have been enabled for a self-hosted model deployment.
METADATA_IPS = {
    "169.254.169.254",   # AWS / Azure / GCP / OpenStack
    "169.254.170.2",     # AWS ECS task metadata
    "169.254.169.253",   # AWS DNS
    "100.100.100.200",   # Alibaba Cloud
    "fd00:ec2::254",     # AWS IPv6
}
METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
}

ALLOWED_SCHEMES = {"http", "https"}


class TargetError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    scheme: str
    host: str
    port: int
    ips: tuple[str, ...]
    private: bool

    @property
    def host_header(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"


def _normalise_host(host: str) -> str:
    host = (host or "").strip().strip("[]").rstrip(".")
    if not host:
        raise TargetError("invalid_host", "目标地址缺少主机名")
    if len(host) > 253:
        raise TargetError("invalid_host", "主机名过长")
    try:
        host.encode("idna")
    except UnicodeError as exc:
        raise TargetError("invalid_host", "主机名包含非法字符") from exc
    return host


def ip_is_blocked(ip: ipaddress._BaseAddress, allow_private: bool) -> tuple[bool, str]:
    if str(ip) in METADATA_IPS:
        return True, "云平台元数据地址被禁止访问"
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return True, f"目标地址 {ip} 属于保留/组播地址"
    if ip.is_loopback:
        return (False, "") if allow_private else (True, "禁止访问本机回环地址")
    if ip.is_link_local:
        return (False, "") if allow_private else (True, "禁止访问链路本地地址")
    if ip.is_private:
        return (False, "") if allow_private else (True, "禁止访问内网地址")
    return False, ""


def resolve_host(host: str, port: int) -> tuple[list[str], str | None]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return [], f"域名解析失败: {exc.strerror or exc}"
    except OSError as exc:
        return [], f"域名解析失败: {exc}"
    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    return ips, None


def validate_url(
    url: str,
    *,
    allow_private: bool | None = None,
    extra_hosts: tuple[str, ...] | None = None,
    blocked_hosts: tuple[str, ...] | None = None,
    require_https: bool = False,
    resolve: bool = True,
) -> ValidatedTarget:
    allow_private = settings.allow_private_upstream if allow_private is None else allow_private
    extra_hosts = settings.upstream_extra_hosts if extra_hosts is None else extra_hosts
    blocked_hosts = settings.upstream_blocked_hosts if blocked_hosts is None else blocked_hosts

    raw = (url or "").strip()
    if not raw:
        raise TargetError("empty_url", "接口地址不能为空")
    if len(raw) > 2048:
        raise TargetError("url_too_long", "接口地址过长（上限 2048 字符）")
    if any(ch in raw for ch in "\r\n\t "):
        raise TargetError("invalid_url", "接口地址包含空白或控制字符")

    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TargetError("invalid_scheme", "仅支持 http/https 协议")
    if require_https and scheme != "https":
        raise TargetError("https_required", "该环境要求使用 HTTPS 接口地址")
    if parts.username or parts.password:
        raise TargetError("url_credentials", "接口地址中不允许包含用户名或密码")
    if parts.fragment:
        raise TargetError("invalid_url", "接口地址不允许包含 URL 片段")

    host = _normalise_host(parts.hostname or "")
    host_l = host.lower()
    if host_l in METADATA_HOSTS:
        raise TargetError("metadata_host", "云平台元数据主机名被禁止访问")
    for suffix in blocked_hosts:
        if host_l == suffix.lstrip(".") or host_l.endswith("." + suffix.lstrip(".")):
            raise TargetError("blocked_host", f"目标主机 {host} 在禁止访问列表中")

    port = parts.port or (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise TargetError("invalid_port", "端口超出范围")

    explicit_allow = host_l in {h.lstrip(".") for h in extra_hosts}
    effective_allow_private = allow_private or explicit_allow

    def check_literal(value: str) -> tuple[bool, str]:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False, ""
        return ip_is_blocked(ip, effective_allow_private)

    if host_l == "localhost":
        if not effective_allow_private:
            raise TargetError("loopback", "禁止访问 localhost")

    blocked, reason = check_literal(host)
    if blocked:
        raise TargetError("blocked_target", reason)

    ips: list[str] = []
    if resolve:
        ips, error = resolve_host(host, port)
        if error:
            raise TargetError("dns_failed", error)
        if not ips:
            raise TargetError("dns_failed", "域名未解析到任何地址")
        for addr in ips:
            blocked, reason = check_literal(addr)
            if blocked:
                raise TargetError("blocked_target", f"{reason}（解析结果 {addr}）")

    return ValidatedTarget(url=raw, scheme=scheme, host=host, port=port, ips=tuple(ips), private=effective_allow_private)


def join_url(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")
