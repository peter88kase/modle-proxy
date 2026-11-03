"""Application entry point."""

from __future__ import annotations

import logging
import logging.handlers
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import auth_api, pages, providers_api, settings_api, shell_api, standards_api, tasks, tasks_api, test_api
from .config import BASE_DIR, settings
from .db import connect, init_db, now_iso
from .security import RateLimiter, client_ip, hash_password, purge_expired_sessions, redact_text, security_headers

APP_VERSION = "1.0.0"

logger = logging.getLogger("bedrock")
_general_limiter = RateLimiter(limit=settings.api_rate_per_minute, window_seconds=60)

MAX_BODY_BYTES = 256 * 1024
# 证据上传走 JSON + base64，2 MB 文件编码后约 2.7 MB，单独放行该前缀
BODY_LIMITS = {"/api/tasks/": 4 * 1024 * 1024}


class RedactFilter(logging.Filter):
    """Last line of defence: no credential pattern may reach a log file."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg, 2000)
        if record.args:
            try:
                record.args = tuple(redact_text(a, 500) if isinstance(a, str) else a for a in record.args)
            except Exception:  # noqa: BLE001
                pass
        return True


def configure_logging() -> None:
    settings.log_path.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    if any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root.handlers):
        return
    root.setLevel(logging.DEBUG if settings.debug else logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")

    file_handler = logging.handlers.RotatingFileHandler(
        settings.log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(RedactFilter())
    root.addHandler(file_handler)

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.addFilter(RedactFilter())
    root.addHandler(console)


def bootstrap_admin() -> None:
    with connect() as conn:
        count = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    if count:
        return
    password = settings.bootstrap_admin_password
    if not password:
        logger.warning(
            "数据库中没有任何账号。请执行 `python -m backend.cli create-user --username admin --role admin` "
            "或设置 BEDROCK_ADMIN_PASSWORD 后重启服务。"
        )
        return
    if len(password) < 12:
        logger.error("BEDROCK_ADMIN_PASSWORD 长度不足 12 位，拒绝创建初始管理员。")
        return
    with connect() as conn:
        conn.execute(
            "INSERT INTO users(username, password_hash, role, is_active, created_at, password_changed_at) "
            "VALUES (?,?,?,1,?,?)",
            (settings.bootstrap_admin_user.lower(), hash_password(password), "admin", now_iso(), now_iso()),
        )
    logger.warning("已根据环境变量创建初始管理员账号 %s，请登录后立即修改密码。", settings.bootstrap_admin_user)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    init_db()
    bootstrap_admin()
    interrupted = tasks.mark_interrupted_tasks()
    if interrupted:
        logger.warning("发现 %s 个上次运行中的测试任务，已标记为中断（凭证随进程释放，需重新执行）。", interrupted)
    purge_expired_sessions()
    if not settings.cookie_secure and settings.env == "production":
        logger.warning("COOKIE_SECURE=false：当前会话 Cookie 不带 Secure 标记，仅适用于 HTTP 内网部署。")
    if settings.allow_private_upstream:
        logger.warning("ALLOW_PRIVATE_UPSTREAM=true：模型测试可访问内网地址，请确认该环境确需测试私有化模型。")
    # BIND_HOST/BIND_PORT 由 systemd 单元的 ExecStart 直接引用，这里打印的就是实际监听地址。
    logger.info("bedrock platform started env=%s listen=%s:%s", settings.env, settings.bind_host, settings.bind_port)
    yield
    logger.info("bedrock platform stopped")


def create_app() -> FastAPI:
    settings.validate()
    app = FastAPI(
        title="AI 模型接口测试与运维辅助平台",
        version=APP_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings

    # 静态资源缓存策略由下面的 `static_cache` 中间件统一加 `no-cache`。
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend" / "static")), name="static")

    @app.middleware("http")
    async def static_cache(request: Request, call_next):
        """给 /static/ 加 `no-cache`：每次带 If-Modified-Since 校验，未变 304。

        为什么需要：前端是 **ES module 链式 import**（app.js → console.js → …），
        URL 里没有内容哈希。浏览器缓存住旧模块后，**即使部署了新代码，用户看到的
        还是旧界面**——这就是"部署上去没看到新功能"。

        为什么不用 `?v=` 查询参数：链式 import 的每一层都要跟着加，漏一层就前功尽弃；
        改响应头一次，全链路生效。
        """
        response = await call_next(request)
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache"
        return response

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        started = time.perf_counter()

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            limit = MAX_BODY_BYTES
            for prefix, prefix_limit in BODY_LIMITS.items():
                if path.startswith(prefix):
                    limit = max(limit, prefix_limit)
            length = request.headers.get("content-length")
            if length and length.isdigit() and int(length) > limit:
                return JSONResponse(
                    status_code=413,
                    content={"ok": False, "error": {"code": "payload_too_large", "message": "请求体超过大小限制"}},
                )

        if path.startswith("/api/"):
            allowed, retry = _general_limiter.allow(f"api:{client_ip(request)}")
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"ok": False, "error": {"code": "rate_limited", "message": "请求过于频繁，请稍后重试"}},
                    headers={"Retry-After": str(retry)},
                )

        response = await call_next(request)
        for key, value in security_headers().items():
            response.headers.setdefault(key, value)
        if path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if request.url.path in {"/", "/shell", "/records", "/settings", "/login", "/manual", "/tasks"}:
            response.headers.setdefault("Cache-Control", "no-store")

        duration_ms = int((time.perf_counter() - started) * 1000)
        logger.info(
            "%s %s %s %sms ip=%s", request.method, path, response.status_code, duration_ms, client_ip(request)
        )
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        detail = exc.detail
        if isinstance(detail, dict):
            payload = {"ok": False, "error": {"code": detail.get("code", "error"), "message": detail.get("message", "")}}
            message = detail.get("message", "")
        else:
            payload = {"ok": False, "error": {"code": "error", "message": str(detail)}}
            message = str(detail)
        if request.url.path.startswith("/api/") or request.headers.get("accept", "").startswith("application/json"):
            return JSONResponse(status_code=exc.status_code, content=payload, headers=exc.headers or {})
        if exc.status_code == 401:
            return RedirectResponse("/login?notice=required", status_code=302)
        return pages.templates.TemplateResponse(
            request, "error.html", {"code": exc.status_code, "message": message, "version": APP_VERSION},
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        # Pydantic errors echo the offending input, which may be a credential.
        safe = [
            {"loc": [str(part) for part in error.get("loc", [])], "msg": error.get("msg", "")}
            for error in exc.errors()
        ]
        first = safe[0] if safe else {"msg": "请求参数不合法"}
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "error": {
                    "code": "validation_error",
                    "message": f"参数错误（{'.'.join(first['loc'])}）：{first['msg']}",
                    "fields": safe,
                },
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        logger.exception("unhandled error on %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": {"code": "internal_error", "message": "服务端处理异常，请查看服务器日志"}},
        )

    app.include_router(auth_api.router)
    app.include_router(providers_api.router)
    app.include_router(test_api.router)
    app.include_router(standards_api.router)
    app.include_router(tasks_api.router)
    app.include_router(shell_api.router)
    app.include_router(settings_api.router)
    app.include_router(pages.router)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "time": now_iso(), "version": APP_VERSION}

    @app.get("/favicon.ico")
    def favicon():
        return RedirectResponse("/static/favicon.svg", status_code=302)

    return app


app = create_app()
