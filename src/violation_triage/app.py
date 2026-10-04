"""启动入口与初始数据引导。"""
from __future__ import annotations

import argparse
import json
import sys

from .config import Settings
from .risk import DEFAULT_RULES
from .service import TriageService

SEED_USERS = [
    ("admin", "admin123", "市级分流管理员", "分流管理员"),
    ("inspector", "inspect123", "市监管人员李监", "监管人员"),
    ("expert", "expert123", "复核专家王核", "复核专家"),
    ("officer", "officer123", "机构合规员周合", "机构合规员"),
    ("practitioner", "pract123", "执业人员吴执", "执业人员"),
]


def seed(service: TriageService, *, reset: bool = False) -> dict:
    """创建演示账号并发布首版风险规则（幂等）。"""
    created_users: list[str] = []
    for username, password, display, role in SEED_USERS:
        exists = service.conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            continue
        service.create_user(username, password, display, role)
        created_users.append(username)
    if service._latest_rule_version(service.conn) is None:
        admin = service.conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        service.publish_rules(admin, DEFAULT_RULES, note="初始风险规则 v1")
        rule_version = 1
    else:
        rule_version = service._latest_rule_version(service.conn)
    return {"created_users": created_users, "rule_version": rule_version}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="违规线索分流处置服务端")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--db", default=None, help="SQLite 路径（默认 triage.db）")
    parser.add_argument("--lease-seconds", type=int, default=None)
    parser.add_argument("--seed", action="store_true", help="启动前写入演示账号与初始规则")
    parser.add_argument("--seed-only", action="store_true", help="只写入初始数据后退出")
    args = parser.parse_args(argv)

    settings = Settings(
        db_path=args.db or Settings().db_path,
        lease_seconds=args.lease_seconds or Settings().lease_seconds,
        host=args.host or Settings().host,
        port=args.port or Settings().port,
    )
    service = TriageService(settings.db_path, lease_seconds=settings.lease_seconds)
    if args.seed or args.seed_only:
        result = seed(service)
        print(json.dumps(result, ensure_ascii=False))
    if args.seed_only:
        return 0

    from .api import make_server

    httpd = make_server(settings, service)
    print(f"违规线索分流处置服务已启动: http://{settings.host}:{settings.port}", flush=True)
    print(f"数据库: {settings.db_path}；租约时长: {settings.lease_seconds} 秒", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n正在关闭…")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
