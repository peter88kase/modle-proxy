"""Authentication, session, CSRF, rate limiting and redaction helpers.

Security decisions implemented here:
* passwords stored with scrypt + per-user salt (stdlib only, no native build)
* sessions are opaque random tokens; only their SHA-256 digest is stored
* CSRF token is bound to the server-side session and required on every
  state-changing request (double check: session cookie + X-CSRF-Token header)
* login throttling is tracked in SQLite so it survives process restarts
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from .config import settings
from .db import connect, now_iso

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_LEN = 32


# --------------------------------------------------------------------------
# password hashing
# --------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_LEN
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(digest_hex)),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# sessions
# --------------------------------------------------------------------------
@dataclass
class SessionContext:
    id_hash: str
    user_id: int
    username: str
    role: str
    csrf_token: str
    created_at: float
    expires_at: float


def create_session(user_id: int, ip: str, user_agent: str) -> tuple[str, SessionContext]:
    sid = new_token(32)
    csrf = new_token(24)
    now = time.time()
    id_hash = digest(sid)
    expires = now + settings.session_idle_seconds
    with connect() as conn:
        conn.execute(
            """INSERT INTO sessions(id_hash, user_id, csrf_token, created_at, last_seen, expires_at, ip, user_agent)
               VALUES (?,?,?,?,?,?,?,?)""",
            (id_hash, user_id, csrf, now, now, expires, ip, user_agent[:200]),
        )
        row = conn.execute("SELECT username, role FROM users WHERE id=?", (user_id,)).fetchone()
    ctx = SessionContext(
        id_hash=id_hash,
        user_id=user_id,
        username=row["username"] if row else "",
        role=row["role"] if row else "operator",
        csrf_token=csrf,
        created_at=now,
        expires_at=expires,
    )
    return sid, ctx


def load_session(sid: str) -> SessionContext | None:
    if not sid or len(sid) > 128:
        return None
    id_hash = digest(sid)
    now = time.time()
    with connect() as conn:
        row = conn.execute(
            """SELECT s.*, u.username, u.role, u.is_active
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.id_hash=?""",
            (id_hash,),
        ).fetchone()
        if row is None or row["revoked"] or not row["is_active"]:
            return None
        if row["expires_at"] <= now or row["created_at"] + settings.session_absolute_seconds <= now:
            conn.execute("DELETE FROM sessions WHERE id_hash=?", (id_hash,))
            return None
        # sliding idle expiry, bounded by the absolute lifetime
        new_expiry = min(now + settings.session_idle_seconds, row["created_at"] + settings.session_absolute_seconds)
        conn.execute("UPDATE sessions SET last_seen=?, expires_at=? WHERE id_hash=?", (now, new_expiry, id_hash))
    return SessionContext(
        id_hash=id_hash,
        user_id=row["user_id"],
        username=row["username"],
        role=row["role"],
        csrf_token=row["csrf_token"],
        created_at=row["created_at"],
        expires_at=new_expiry,
    )


def destroy_session(id_hash: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE id_hash=?", (id_hash,))


def destroy_user_sessions(user_id: int, keep: str | None = None) -> int:
    with connect() as conn:
        if keep:
            cur = conn.execute("DELETE FROM sessions WHERE user_id=? AND id_hash<>?", (user_id, keep))
        else:
            cur = conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        return cur.rowcount


def purge_expired_sessions() -> None:
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))


# --------------------------------------------------------------------------
# login throttling
# --------------------------------------------------------------------------
def record_login(ip: str, username: str, success: bool) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO login_attempts(ts, ip, username, success) VALUES (?,?,?,?)",
            (time.time(), ip, username.lower()[:80], 1 if success else 0),
        )
        # keep the table small
        conn.execute("DELETE FROM login_attempts WHERE ts < ?", (time.time() - 7 * 86400,))


def login_blocked(ip: str, username: str) -> tuple[bool, int]:
    """Return (blocked, retry_after_seconds).

    Two independent counters: per source IP and per account, so neither a
    single-IP brute force nor a distributed attack against one account passes.
    """
    now = time.time()
    window_start = now - settings.login_window_seconds
    with connect() as conn:
        ip_fail = conn.execute(
            "SELECT COUNT(*) c, MAX(ts) last FROM login_attempts WHERE ip=? AND success=0 AND ts>=?",
            (ip, window_start),
        ).fetchone()
        user_fail = conn.execute(
            "SELECT COUNT(*) c, MAX(ts) last FROM login_attempts WHERE username=? AND success=0 AND ts>=?",
            (username.lower(), window_start),
        ).fetchone()
        lock_until = 0.0
        for row in (ip_fail, user_fail):
            if row["c"] >= settings.login_max_failures:
                lock_until = max(lock_until, (row["last"] or now) + settings.login_lock_seconds)
    if lock_until > now:
        return True, int(lock_until - now) + 1
    return False, 0


def clear_login_failures(ip: str, username: str) -> None:
    with connect() as conn:
        conn.execute(
            "DELETE FROM login_attempts WHERE ip=? AND username=? AND success=0",
            (ip, username.lower()),
        )


# --------------------------------------------------------------------------
# generic sliding-window limiter (per process)
# --------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        now = time.time()
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] < now - self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                retry = int(self.window - (now - bucket[0])) + 1
                return False, retry
            bucket.append(now)
            return True, 0


# --------------------------------------------------------------------------
# redaction
# --------------------------------------------------------------------------
_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{6,}"),
    re.compile(r"(?i)(x-api-key\s*[:=]\s*)[^\s\"',]{4,}"),
    re.compile(r"(?i)(api[_-]?key[\"']?\s*[:=]\s*[\"']?)[^\s\"',&]{4,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{6,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b"),
    re.compile(r"(?i)(secret[_-]?key[\"']?\s*[:=]\s*[\"']?)[^\s\"',&]{4,}"),
]
_URL_QUERY = re.compile(r"(?i)([?&](?:key|api_key|apikey|access_token|token|sig|signature)=)[^&\s]+")


def redact_text(value: Any, limit: int = 400) -> str:
    text = "" if value is None else str(value)
    for pattern in _PATTERNS:
        text = pattern.sub(lambda m: (m.group(1) if m.groups() else "") + "***", text)
    text = text.replace("\r", " ").replace("\n", " ")
    return text[:limit]


def redact_url(url: str) -> str:
    return _URL_QUERY.sub(r"\1***", url)


def looks_like_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in _PATTERNS)


# --------------------------------------------------------------------------
# request identity
# --------------------------------------------------------------------------
def client_ip(request) -> str:
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
        real = request.headers.get("x-real-ip")
        if real:
            return real.strip()[:64]
    return request.client.host if request.client else "unknown"


def security_headers() -> dict[str, str]:
    return {
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        ),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }


def utc_stamp() -> str:
    return now_iso()
