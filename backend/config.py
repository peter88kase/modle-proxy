"""Runtime configuration for the Bedrock AI endpoint test platform.

All values come from environment variables or a .env file that is loaded by the
service manager (systemd EnvironmentFile).  No secret is ever compiled into the
source code, and no secret is written to the database.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _str(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    return default if value is None or value == "" else value


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:  # fail fast on a broken deployment file
        raise RuntimeError(f"环境变量 {name} 必须是整数，当前值: {raw!r}") from exc


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:  # fail fast on a broken deployment file
        raise RuntimeError(f"环境变量 {name} 必须是数字，当前值: {raw!r}") from exc


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _csv(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(part.strip().lower() for part in raw.split(",") if part.strip())


def _load_dotenv(path: Path) -> None:
    """Minimal .env reader so `python -m uvicorn` works without extra deps.

    Existing environment variables always win over the file.
    """
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(BASE_DIR / ".env")


@dataclass(frozen=True)
class Settings:
    # --- basic ---------------------------------------------------------
    app_name: str = "AI 模型接口测试与运维辅助平台"
    env: str = _str("APP_ENV", "production")
    debug: bool = _bool("APP_DEBUG", False)
    bind_host: str = _str("BIND_HOST", "127.0.0.1")
    bind_port: int = _int("BIND_PORT", 8000)
    base_path: str = _str("BASE_PATH", "").rstrip("/")
    public_origin: str = _str("PUBLIC_ORIGIN", "")

    # --- storage -------------------------------------------------------
    db_path: Path = Path(_str("DB_PATH", str(BASE_DIR / "data" / "bedrock.db")))
    log_path: Path = Path(_str("LOG_PATH", str(BASE_DIR / "logs" / "bedrock.log")))

    # --- sessions ------------------------------------------------------
    cookie_name: str = _str("SESSION_COOKIE_NAME", "bedrock_sid")
    cookie_secure: bool = _bool("COOKIE_SECURE", False)
    cookie_domain: str = _str("COOKIE_DOMAIN", "")
    session_idle_seconds: int = _int("SESSION_IDLE_SECONDS", 30 * 60)
    session_absolute_seconds: int = _int("SESSION_ABSOLUTE_SECONDS", 8 * 3600)

    # --- login protection ---------------------------------------------
    login_max_failures: int = _int("LOGIN_MAX_FAILURES", 5)
    login_window_seconds: int = _int("LOGIN_WINDOW_SECONDS", 15 * 60)
    login_lock_seconds: int = _int("LOGIN_LOCK_SECONDS", 15 * 60)
    password_min_length: int = _int("PASSWORD_MIN_LENGTH", 12)
    login_rate_per_minute: int = _int("LOGIN_RATE_PER_MINUTE", 12)
    api_rate_per_minute: int = _int("API_RATE_PER_MINUTE", 240)
    bootstrap_admin_password: str = _str("BEDROCK_ADMIN_PASSWORD", "")
    bootstrap_admin_user: str = _str("BEDROCK_ADMIN_USER", "admin")

    # --- upstream model calls -----------------------------------------
    model_connect_timeout: float = float(_str("MODEL_CONNECT_TIMEOUT", "10"))
    model_first_token_timeout: float = float(_str("MODEL_FIRST_TOKEN_TIMEOUT", "30"))
    model_total_timeout: float = float(_str("MODEL_TOTAL_TIMEOUT", "60"))
    model_max_body_bytes: int = _int("MODEL_MAX_BODY_BYTES", 2 * 1024 * 1024)
    model_max_concurrency: int = _int("MODEL_MAX_CONCURRENCY", 6)
    #: 相邻两次上游请求的默认最小间隔（秒）。0 = 不限速。
    #: 任务/单次测试显式填了 request_interval 时以填的为准，这里只是兜底默认值。
    model_request_interval: float = _float("MODEL_REQUEST_INTERVAL", 2.0)
    model_repeat: int = _int("MODEL_REPEAT", 3)
    allow_private_upstream: bool = _bool("ALLOW_PRIVATE_UPSTREAM", False)
    upstream_extra_hosts: tuple[str, ...] = _csv("UPSTREAM_EXTRA_HOSTS")
    upstream_blocked_hosts: tuple[str, ...] = _csv("UPSTREAM_BLOCKED_HOSTS")
    user_agent: str = _str("UPSTREAM_USER_AGENT", "bedrock-endpoint-test/1.0")

    # --- shell worker --------------------------------------------------
    shell_enabled: bool = _bool("SHELL_ENABLED", True)
    shell_socket: str = _str("SHELL_SOCKET", "/run/bedrock/shell.sock")
    shell_host: str = _str("SHELL_HOST", "127.0.0.1")
    shell_port: int = _int("SHELL_PORT", 9700)
    shell_token: str = _str("SHELL_TOKEN", "")
    shell_request_timeout: float = float(_str("SHELL_REQUEST_TIMEOUT", "45"))
    shell_rate_per_minute: int = _int("SHELL_RATE_PER_MINUTE", 30)

    # --- misc ----------------------------------------------------------
    trust_proxy_headers: bool = _bool("TRUST_PROXY_HEADERS", False)
    allowed_origins: tuple[str, ...] = _csv("ALLOWED_ORIGINS")
    providers_seed: Path = Path(_str("PROVIDERS_SEED", str(BASE_DIR / "config" / "providers.json")))

    def validate(self) -> None:
        if self.shell_enabled and not self.shell_token:
            raise RuntimeError(
                "SHELL_TOKEN 未配置。主服务与 Shell 工作进程之间的调用必须使用共享令牌，"
                "请参考 .env.example 生成随机值。"
            )

    @property
    def cookie_path(self) -> str:
        return self.base_path or "/"


settings = Settings()
