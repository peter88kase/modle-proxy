"""SQLite storage layer.

Only non-sensitive data is persisted: accounts (salted password hashes),
server-side sessions (hashed identifiers), provider configuration, acceptance
records and audit metadata.  Test credentials are never written here.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .config import settings

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'operator',
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL,
    password_changed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id_hash      TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_at   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    expires_at   REAL NOT NULL,
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT '',
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    ip        TEXT NOT NULL,
    username  TEXT NOT NULL,
    success   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_ts ON login_attempts(ts);

CREATE TABLE IF NOT EXISTS providers (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    adapter            TEXT NOT NULL,
    direct_base_url    TEXT NOT NULL DEFAULT '',
    forward_base_url   TEXT NOT NULL DEFAULT '',
    auth_style         TEXT NOT NULL DEFAULT 'bearer',
    default_model      TEXT NOT NULL DEFAULT '',
    protocols          TEXT NOT NULL DEFAULT '[]',
    notes              TEXT NOT NULL DEFAULT '',
    enabled            INTEGER NOT NULL DEFAULT 1,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS suite_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    user_id       INTEGER,
    provider_id   TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    adapter       TEXT NOT NULL,
    link          TEXT NOT NULL,
    model         TEXT NOT NULL,
    endpoint_host TEXT NOT NULL,
    passed        INTEGER NOT NULL DEFAULT 0,
    failed        INTEGER NOT NULL DEFAULT 0,
    skipped       INTEGER NOT NULL DEFAULT 0,
    note          TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS suite_cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES suite_runs(id) ON DELETE CASCADE,
    case_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    result      TEXT NOT NULL,
    evidence    TEXT NOT NULL DEFAULT '',
    http_status INTEGER,
    latency_ms  INTEGER,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_run ON suite_cases(run_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    user_id    INTEGER,
    username   TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    ip         TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS runtime_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 第 1～4 章测试标准：版本不可变，修改即生成新版本，历史测试记录始终指向当时的版本
CREATE TABLE IF NOT EXISTS standard_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    standard_id     TEXT    NOT NULL,
    version         TEXT    NOT NULL,
    source_document TEXT    NOT NULL DEFAULT '',
    item_count      INTEGER NOT NULL,
    checksum        TEXT    NOT NULL,
    parent_id       INTEGER,
    created_by      TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL,
    note            TEXT    NOT NULL DEFAULT '',
    -- 键方案：legacy_id = item_id 就是原文编号；item_key = item_id 存 ch{N}:{id}。
    -- 历史版本一律 legacy_id（不推断、不改写），新版本一律 item_key。
    key_scheme      TEXT    NOT NULL DEFAULT 'legacy_id',
    -- 章节结构快照（JSON）。报告只能读这里，不得读当前 config 文件，
    -- 否则改一次标准，历史批次的章节标题会跟着变。
    chapters        TEXT    NOT NULL DEFAULT '[]',
    -- definition = 创建时即写快照；backfill = 迁移时用当时的定义回填（必须声明）
    chapters_source TEXT    NOT NULL DEFAULT 'backfill'
);

-- 版本标签在同一 standard_id 内必须唯一：没有这条约束，标签撞车会静默发生，
-- 于是出现"两行同标签、不同 checksum"，版本不可变就此失效。
CREATE UNIQUE INDEX IF NOT EXISTS ux_std_version_label ON standard_versions(standard_id, version);

CREATE TABLE IF NOT EXISTS standard_items (
    version_id  INTEGER NOT NULL REFERENCES standard_versions(id) ON DELETE CASCADE,
    item_id     TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    requirement TEXT    NOT NULL DEFAULT 'mandatory',
    params      TEXT    NOT NULL DEFAULT '{}',
    chapter     INTEGER NOT NULL DEFAULT 0,
    display_id  TEXT    NOT NULL DEFAULT '',
    item_key    TEXT    NOT NULL DEFAULT '',
    order_index INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, item_id)
);

-- 同一版本内 item_key 唯一。必须带 `WHERE item_key <> ''`：历史版本整版
-- item_key 都是空串（legacy 语义），全列唯一索引会让第二个历史项直接插不进去。
-- 索引在 _ensure_indexes() 里创建（ALTER 加列之后），不能放在 SCHEMA 里：
-- 老库执行 SCHEMA 时 item_key 列还不存在。

-- 硬断言检查点（9 行 / 5 分母）。与 166 项主分母分开存，绝不并进 standard_items：
-- 并进去 item_count 会变 175，所有「166」口径当场失效。
CREATE TABLE IF NOT EXISTS standard_checkpoints (
    version_id   INTEGER NOT NULL REFERENCES standard_versions(id) ON DELETE CASCADE,
    checkpoint   TEXT    NOT NULL,
    display_code TEXT    NOT NULL,
    chapter      INTEGER NOT NULL DEFAULT 0,
    code_kind    TEXT    NOT NULL DEFAULT 'platform_checkpoint_not_original_id',
    proxy_of     TEXT    NOT NULL DEFAULT '',
    counted      INTEGER NOT NULL DEFAULT 0,
    payload      TEXT    NOT NULL DEFAULT '{}',
    enabled      INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (version_id, checkpoint)
);

-- 每次测试批次对每个标准项的判定结果（自动检查或人工确认）
CREATE TABLE IF NOT EXISTS run_items (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER NOT NULL REFERENCES suite_runs(id) ON DELETE CASCADE,
    item_id    TEXT    NOT NULL,
    status     TEXT    NOT NULL,
    source     TEXT    NOT NULL DEFAULT 'manual',
    actual     TEXT    NOT NULL DEFAULT '',
    evidence   TEXT    NOT NULL DEFAULT '',
    note       TEXT    NOT NULL DEFAULT '',
    operator   TEXT    NOT NULL DEFAULT '',
    updated_at TEXT    NOT NULL,
    -- item_key = 该批次所用标准版本的版本内键（ch{N}:{id}；历史行回填为 item_id）。
    -- item_id 仍是原文编号（报告与人工复核按它对原文），也是回滚锚点。
    item_key   TEXT    NOT NULL DEFAULT '',
    display_id TEXT    NOT NULL DEFAULT '',
    UNIQUE(run_id, item_id)
);
CREATE INDEX IF NOT EXISTS idx_run_items_run ON run_items(run_id);
-- 同一批次内 item_key 唯一；item_key 为空说明写入方漏传，重复空串会被这里挡下来。
-- 同样在 _ensure_indexes() 里建（老库加列顺序问题）。

-- 供应商自动化验收任务：任务 = 一次完整验收的执行单元，run_id 指向它产生的执行记录。
-- 只保存非敏感元数据；API Key 仅存在于后台任务的内存中，任务结束即释放。
CREATE TABLE IF NOT EXISTS test_tasks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at          TEXT    NOT NULL,
    started_at          TEXT    NOT NULL DEFAULT '',
    finished_at         TEXT    NOT NULL DEFAULT '',
    user_id             INTEGER,
    username            TEXT    NOT NULL DEFAULT '',
    name                TEXT    NOT NULL,
    provider_id         TEXT    NOT NULL DEFAULT 'custom',
    adapter             TEXT    NOT NULL,
    model               TEXT    NOT NULL,
    endpoint_host       TEXT    NOT NULL DEFAULT '',
    endpoint_masked     TEXT    NOT NULL DEFAULT '',
    link                TEXT    NOT NULL DEFAULT 'direct',
    standard_version_id INTEGER,
    standard_version    TEXT    NOT NULL DEFAULT '',
    standard_checksum   TEXT    NOT NULL DEFAULT '',
    status              TEXT    NOT NULL DEFAULT 'queued',
    phase               TEXT    NOT NULL DEFAULT 'ch1',
    progress_done       INTEGER NOT NULL DEFAULT 0,
    progress_total      INTEGER NOT NULL DEFAULT 0,
    counts              TEXT    NOT NULL DEFAULT '{}',
    conclusion          TEXT    NOT NULL DEFAULT '',
    stop_reason         TEXT    NOT NULL DEFAULT '',
    run_id              INTEGER,
    parent_task_id      INTEGER,
    -- 多模型批量：同一次提交里的每个模型一个任务，靠 batch_id 归组，
    -- 这样"一次提交跑 5 个模型"能出一份合并报告，而不是 5 份互不相干的报告。
    batch_id            TEXT    NOT NULL DEFAULT '',
    attempt             INTEGER NOT NULL DEFAULT 1,
    budget              TEXT    NOT NULL DEFAULT '{}',
    options             TEXT    NOT NULL DEFAULT '{}',
    error               TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tasks_run ON test_tasks(run_id);
CREATE INDEX IF NOT EXISTS idx_tasks_user ON test_tasks(user_id);

-- 一个任务内的模型明细：任务 = 一次提交，task_runs = 其中的每个模型。
-- 每个模型仍各自一条 suite_runs（run_items 对 (run_id,item_id) 唯一，
-- 同一用例的多模型结果必须分表存），但生命周期、删除、报告都归到同一个 task_id。
CREATE TABLE IF NOT EXISTS task_runs (
    task_id        INTEGER NOT NULL REFERENCES test_tasks(id) ON DELETE CASCADE,
    model          TEXT    NOT NULL,
    run_id         INTEGER NOT NULL,
    status         TEXT    NOT NULL DEFAULT 'queued',
    conclusion     TEXT    NOT NULL DEFAULT '',
    counts         TEXT    NOT NULL DEFAULT '{}',
    progress_done  INTEGER NOT NULL DEFAULT 0,
    progress_total INTEGER NOT NULL DEFAULT 0,
    stop_reason    TEXT    NOT NULL DEFAULT '',
    -- 前置必测量出的渠道指标（JSON：P5/中位/P95、缓存命中率）。作为该渠道权重依据。
    metrics        TEXT    NOT NULL DEFAULT '{}',
    created_at     TEXT    NOT NULL,
    finished_at    TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (task_id, model),
    UNIQUE (run_id)
);
CREATE INDEX IF NOT EXISTS idx_task_runs_task ON task_runs(task_id);

-- 人工确认的证据文件（截图、脱敏日志、账单截图等）。文件存 data/evidence/，
-- 这里只记录文件名、大小、摘要与上传人，不保存文件内容。
CREATE TABLE IF NOT EXISTS manual_evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     INTEGER NOT NULL REFERENCES test_tasks(id) ON DELETE CASCADE,
    item_id     TEXT    NOT NULL,
    filename    TEXT    NOT NULL,
    stored_name TEXT    NOT NULL,
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    sha256      TEXT    NOT NULL DEFAULT '',
    note        TEXT    NOT NULL DEFAULT '',
    uploaded_by TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_task ON manual_evidence(task_id, item_id);

-- 单用例重测审计：更新 run_items 前先把旧判定记下来，历史失败证据不被覆盖丢失。
CREATE TABLE IF NOT EXISTS retest_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL REFERENCES test_tasks(id) ON DELETE CASCADE,
    item_id         TEXT    NOT NULL,
    scope           TEXT    NOT NULL DEFAULT 'item',
    previous_status TEXT    NOT NULL DEFAULT '',
    previous_actual TEXT    NOT NULL DEFAULT '',
    new_status      TEXT    NOT NULL DEFAULT '',
    new_actual      TEXT    NOT NULL DEFAULT '',
    operator        TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_retest_task ON retest_log(task_id);
"""

# 旧库升级：为已存在的 suite_runs 补齐标准绑定与结论列
MIGRATIONS = {
    # B0.5b：版本号位置是**协议变体**，不能靠猜。
    # AWS 文档：bedrock-runtime 的 InvokeModel 把版本放 body（bedrock-2023-05-31），
    # Anthropic 直连 / bedrock-mantle 放 header（2023-06-01）。二选一。
    # 放在 provider 上（而不是每个任务填），因为一个网关固定一种写法。
    "providers": [
        ("api_version", "TEXT NOT NULL DEFAULT ''"),
        ("version_in_body", "INTEGER NOT NULL DEFAULT 0"),
    ],
    # blocked 必须由枚举驱动（规格 §2.3）：加列而不是塞进 note，
    # 否则 B0.5 只能靠解析自由文本回填，正是这轮反复在堵的不可靠。
    "run_items": [
        ("blocker_reason", "TEXT NOT NULL DEFAULT ''"),
        # B0.5b：版本内键与显示编号分列。item_id 保持原文编号（回滚锚点）。
        ("item_key", "TEXT NOT NULL DEFAULT ''"),
        ("display_id", "TEXT NOT NULL DEFAULT ''"),
    ],
    "suite_runs": [
        ("standard_version_id", "INTEGER"),
        ("standard_version", "TEXT NOT NULL DEFAULT ''"),
        ("standard_checksum", "TEXT NOT NULL DEFAULT ''"),
        ("conclusion", "TEXT NOT NULL DEFAULT ''"),
    ],
    "standard_versions": [
        # 历史版本默认 legacy_id：不推断、不改写，读的时候按 item_id 回溯。
        ("key_scheme", "TEXT NOT NULL DEFAULT 'legacy_id'"),
        # 章节快照。默认空数组，由 _backfill() 用"当时的定义"回填并标 chapters_source。
        ("chapters", "TEXT NOT NULL DEFAULT '[]'"),
        ("chapters_source", "TEXT NOT NULL DEFAULT 'backfill'"),
    ],
    # 多模型批次的归组键。老任务留空串（= 不属于任何批次），不推测历史数据。
    "test_tasks": [
        ("batch_id", "TEXT NOT NULL DEFAULT ''"),
        # 同一任务里要测的模型（JSON 数组，顺序即执行顺序）。
        # 历史任务为空数组，读取时回退到单列 model。
        ("models", "TEXT NOT NULL DEFAULT '[]'"),
    ],
    "task_runs": [
        # 前置必测的渠道指标（延时 P5/中位/P95、缓存命中率），供渠道权重使用。
        ("metrics", "TEXT NOT NULL DEFAULT '{}'"),
    ],
    "standard_items": [
        ("chapter", "INTEGER NOT NULL DEFAULT 0"),
        ("display_id", "TEXT NOT NULL DEFAULT ''"),
        ("item_key", "TEXT NOT NULL DEFAULT ''"),
        ("order_index", "INTEGER NOT NULL DEFAULT 0"),
    ],
}

# SQLite 只允许一个写者；同一进程内多个事件循环/线程（例如 TestClient 的
# portal 线程与主线程）同时写入时，Windows 上会出现
# “attempt to write a readonly database”。用进程内可重入锁串行化连接生命周期。
_DB_LOCK = threading.RLock()

DEFAULT_RUNTIME_SETTINGS = {
    "test_repeat": str(settings.model_repeat),
    "default_prompt": "只回复 CONNECT_OK",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def db_file() -> Path:
    return settings.db_path


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    path = db_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _DB_LOCK:
        conn = sqlite3.connect(path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        # 后台任务与页面轮询会并发读写同一个库；给 SQLite 一个等待窗口，
        # 避免瞬时锁冲突被当成“任务失败”。
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
        finally:
            conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)
        _backfill(conn)
        _ensure_indexes(conn)
        for key, value in DEFAULT_RUNTIME_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO runtime_settings(key, value, updated_at) VALUES (?,?,?)",
                (key, value, now_iso()),
            )
    seed_providers()
    seed_standard_version()


def _migrate(conn: sqlite3.Connection) -> None:
    """Additive-only migration: new columns on pre-existing tables.

    CREATE TABLE IF NOT EXISTS never alters an existing table, so columns added
    after a database was first created must be appended explicitly.
    """
    for table, columns in MIGRATIONS.items():
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if not existing:
            continue
        for name, decl in columns:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def _backfill(conn: sqlite3.Connection) -> dict[str, int]:
    """B0.5b 回填：只写新增列，不动 item_id / status / actual / note / operator。

    幂等：结果完全由 payload 与 item_id 决定，重复执行不改变数据。
    单事务执行，并在前后各数一次行数——行数变了就说明写错了地方，直接回滚。

    历史版本的语义必须保持"当时是什么就是什么"：
    * `key_scheme` 保持 `legacy_id`（不把新方案倒推给旧版本）；
    * `item_key` 保持空串（`Version.items` 用原文编号做键，不需要版本内键）；
    * `chapters` 只能用当前定义回填，因此必须标 `chapters_source='backfill'`，
      由报告显式声明"标题若与当年不符以 source_document 为准"。
    """
    counts_before = {
        table: int(conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"])
        for table in ("standard_versions", "standard_items", "run_items")
    }
    report: dict[str, int] = {}
    conn.execute("BEGIN IMMEDIATE")
    try:
        # 1) 历史版本缺章节快照 → 用当前定义回填，并标记来源
        pending = conn.execute(
            "SELECT id FROM standard_versions WHERE chapters IS NULL OR chapters IN ('', '[]')"
        ).fetchall()
        if pending:
            from .standards import shipped_chapters  # 局部 import：避免 db ↔ standards 循环

            snapshot = json.dumps(shipped_chapters(), ensure_ascii=False)
            for row in pending:
                conn.execute(
                    "UPDATE standard_versions SET chapters=?, chapters_source='backfill' WHERE id=?",
                    (snapshot, int(row["id"])),
                )
            report["versions_chapters_backfilled"] = len(pending)

        # 2) standard_items：chapter / display_id / item_key / order_index 由 payload 派生
        schemes = {
            int(row["id"]): str(row["key_scheme"] or "legacy_id")
            for row in conn.execute("SELECT id, key_scheme FROM standard_versions")
        }
        rank = _shipped_rank()
        touched = 0
        rows = conn.execute(
            "SELECT version_id, item_id, payload, chapter, display_id, item_key, order_index "
            "FROM standard_items"
        ).fetchall()
        per_version_index: dict[int, int] = {}
        for row in rows:
            version_id = int(row["version_id"])
            payload = json.loads(row["payload"])
            chapter = int(payload.get("chapter") or 0)
            display_id = str(payload.get("display_id") or payload.get("id") or row["item_id"])
            scheme = schemes.get(version_id, "legacy_id")
            item_key = row["item_id"] if scheme == "item_key" else ""
            position = rank.get(display_id)
            if position is None:
                position = 10000 + per_version_index.get(version_id, 0)
                per_version_index[version_id] = per_version_index.get(version_id, 0) + 1
            if (
                int(row["chapter"]) != chapter
                or str(row["display_id"]) != display_id
                or str(row["item_key"]) != item_key
                or int(row["order_index"]) != position
            ):
                conn.execute(
                    "UPDATE standard_items SET chapter=?, display_id=?, item_key=?, order_index=? "
                    "WHERE version_id=? AND item_id=?",
                    (chapter, display_id, item_key, position, version_id, row["item_id"]),
                )
                touched += 1
        if touched:
            report["standard_items_rows"] = touched

        # 3) run_items：item_key / display_id 以 item_id 为准回填（每批次的原文编号不变）
        cursor = conn.execute(
            "UPDATE run_items SET display_id=item_id WHERE display_id='' AND item_id<>''"
        )
        if cursor.rowcount:
            report["run_items_display_id"] = cursor.rowcount
        cursor = conn.execute("UPDATE run_items SET item_key=item_id WHERE item_key='' AND item_id<>''")
        if cursor.rowcount:
            report["run_items_item_key"] = cursor.rowcount

        counts_after = {
            table: int(conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"])
            for table in ("standard_versions", "standard_items", "run_items")
        }
        if counts_after != counts_before:
            raise RuntimeError(f"回填前后行数不一致，已回滚：{counts_before} → {counts_after}")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return report


def _shipped_rank() -> dict[str, int]:
    """包内定义里每个原文编号的顺序位；取不到就退化为空表（按插入顺序排）。"""
    try:
        from .standards import definition

        return {str(raw["id"]): index for index, raw in enumerate(definition()["items"])}
    except Exception:  # pragma: no cover - 定义缺失时不影响迁移
        return {}


def _ensure_indexes(conn: sqlite3.Connection) -> None:
    """索引必须在加列 + 回填之后建。

    两类坑同一个原因：``SCHEMA`` 是 ``CREATE TABLE IF NOT EXISTS``，对已存在的表
    **不会加列**，所以 schema 里任何引用新列的 ``CREATE INDEX`` 都会在迁移之前执行、
    直接抛 ``no such column``，整个 ``init_db`` 连启动都过不去（线上升过级就会撞）。
    * 唯一索引会因为"整列空串"建不起来；
    * 引用新增列的普通索引会因为"列还不存在"建不起来。
    """
    # batch_id 是 MIGRATIONS 加的列，索引只能在这里建（见上）。
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_batch ON test_tasks(batch_id)")
    try:
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_items_key "
            "ON standard_items(version_id, item_key) WHERE item_key <> ''"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_run_items_key ON run_items(run_id, item_key)"
        )
    except sqlite3.IntegrityError as exc:  # pragma: no cover - 需要真实脏数据才能触发
        raise RuntimeError(f"唯一索引建立失败（存在重复 item_key）：{exc}") from exc


def seed_standard_version() -> None:
    """Create the first standard version, or append one when the packaged definition changed."""
    from .standards import ensure_seed_version, sync_definition

    ensure_seed_version()
    sync_definition()


def seed_providers() -> None:
    """Insert seed providers once; existing rows are never overwritten."""
    import json

    path = settings.providers_seed
    if not path.is_file():
        return
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    with connect() as conn:
        for item in entries:
            conn.execute(
                """INSERT OR IGNORE INTO providers
                   (id, name, adapter, direct_base_url, forward_base_url, auth_style,
                    default_model, protocols, notes, enabled, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    item["id"],
                    item["name"],
                    item["adapter"],
                    item.get("direct_base_url", ""),
                    item.get("forward_base_url", ""),
                    item.get("auth_style", "bearer"),
                    item.get("default_model", ""),
                    json.dumps(item.get("protocols", []), ensure_ascii=False),
                    item.get("notes", ""),
                    1 if item.get("enabled", True) else 0,
                    now_iso(),
                    now_iso(),
                ),
            )


def audit(user_id: int | None, username: str, action: str, ip: str, detail: str = "") -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit_log(ts, user_id, username, action, ip, detail) VALUES (?,?,?,?,?,?)",
            (now_iso(), user_id, username, action, ip, detail[:500]),
        )


def get_runtime_int(key: str, fallback: int) -> int:
    with connect() as conn:
        row = conn.execute("SELECT value FROM runtime_settings WHERE key=?", (key,)).fetchone()
    if not row:
        return fallback
    try:
        return int(row["value"])
    except (TypeError, ValueError):
        return fallback


def set_runtime_setting(key: str, value: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO runtime_settings(key, value, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, now_iso()),
        )


def all_runtime_settings() -> dict[str, str]:
    with connect() as conn:
        rows = conn.execute("SELECT key, value FROM runtime_settings ORDER BY key").fetchall()
    return {row["key"]: row["value"] for row in rows}
