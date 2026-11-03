"""Command line utilities: database init, account management, maintenance.

Usage:
    python -m backend.cli init-db
    python -m backend.cli create-user --username alice --role operator
    python -m backend.cli reset-password --username alice
    python -m backend.cli list-users
    python -m backend.cli purge-sessions
"""

from __future__ import annotations

import argparse
import getpass
import sys

from .config import settings
from .db import connect, init_db, now_iso
from .security import hash_password, purge_expired_sessions, verify_password


def _read_password(prompt: str) -> str:
    if sys.stdin.isatty():
        first = getpass.getpass(prompt)
        second = getpass.getpass("再次输入以确认: ")
        if first != second:
            raise SystemExit("两次输入的密码不一致")
        return first
    # non-interactive: read from stdin (used by provisioning scripts)
    return sys.stdin.readline().strip()


def cmd_init_db(_: argparse.Namespace) -> int:
    init_db()
    print(f"数据库已初始化: {settings.db_path}")
    return 0


def cmd_create_user(args: argparse.Namespace) -> int:
    init_db()
    username = args.username.strip().lower()
    if not username:
        raise SystemExit("用户名不能为空")
    password = args.password or _read_password("设置密码: ")
    if len(password) < settings.password_min_length:
        raise SystemExit(f"密码长度至少 {settings.password_min_length} 位")
    with connect() as conn:
        exists = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if exists:
            raise SystemExit(f"用户 {username} 已存在")
        conn.execute(
            "INSERT INTO users(username, password_hash, role, is_active, created_at, password_changed_at) "
            "VALUES (?,?,?,1,?,?)",
            (username, hash_password(password), args.role, now_iso(), now_iso()),
        )
    print(f"已创建用户 {username}（角色 {args.role}）")
    return 0


def cmd_reset_password(args: argparse.Namespace) -> int:
    username = args.username.strip().lower()
    password = args.password or _read_password("新密码: ")
    if len(password) < settings.password_min_length:
        raise SystemExit(f"密码长度至少 {settings.password_min_length} 位")
    with connect() as conn:
        row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            raise SystemExit(f"用户 {username} 不存在")
        conn.execute(
            "UPDATE users SET password_hash=?, password_changed_at=? WHERE id=?",
            (hash_password(password), now_iso(), row["id"]),
        )
        conn.execute("DELETE FROM sessions WHERE user_id=?", (row["id"],))
    print(f"已重置 {username} 的密码，该用户所有会话已失效")
    return 0


def cmd_list_users(_: argparse.Namespace) -> int:
    with connect() as conn:
        rows = conn.execute("SELECT id, username, role, is_active, created_at FROM users ORDER BY id").fetchall()
    if not rows:
        print("暂无用户")
        return 0
    for row in rows:
        state = "启用" if row["is_active"] else "禁用"
        print(f"{row['id']:>3}  {row['username']:<20} {row['role']:<10} {state}  {row['created_at']}")
    return 0


def cmd_disable_user(args: argparse.Namespace) -> int:
    with connect() as conn:
        conn.execute("UPDATE users SET is_active=0 WHERE username=?", (args.username.lower(),))
        conn.execute("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username=?)", (args.username.lower(),))
    print(f"用户 {args.username} 已禁用，会话已失效")
    return 0


def cmd_purge_sessions(_: argparse.Namespace) -> int:
    purge_expired_sessions()
    print("过期会话已清理")
    return 0


def cmd_verify_password(args: argparse.Namespace) -> int:
    with connect() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE username=?", (args.username.lower(),)).fetchone()
    ok = bool(row) and verify_password(args.password, row["password_hash"])
    print("匹配" if ok else "不匹配")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bedrock", description="平台运维命令")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db").set_defaults(func=cmd_init_db)
    sub.add_parser("list-users").set_defaults(func=cmd_list_users)
    sub.add_parser("purge-sessions").set_defaults(func=cmd_purge_sessions)

    create = sub.add_parser("create-user")
    create.add_argument("--username", required=True)
    create.add_argument("--role", choices=["admin", "operator", "viewer"], default="operator")
    create.add_argument("--password", default="")
    create.set_defaults(func=cmd_create_user)

    reset = sub.add_parser("reset-password")
    reset.add_argument("--username", required=True)
    reset.add_argument("--password", default="")
    reset.set_defaults(func=cmd_reset_password)

    disable = sub.add_parser("disable-user")
    disable.add_argument("--username", required=True)
    disable.set_defaults(func=cmd_disable_user)

    verify = sub.add_parser("verify-password")
    verify.add_argument("--username", required=True)
    verify.add_argument("--password", required=True)
    verify.set_defaults(func=cmd_verify_password)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
