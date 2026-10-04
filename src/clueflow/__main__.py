"""服务入口：python3 -m clueflow [--host H] [--port P] [--db PATH]"""
from __future__ import annotations

import argparse

from .api import create_server
from .services import ClueflowService
from .store import Store


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="clueflow", description="违规线索分流处置服务端")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", default="clueflow.db", help="SQLite 数据库路径，:memory: 为内存库")
    args = parser.parse_args(argv)

    service = ClueflowService(Store(args.db))
    server = create_server(service, args.host, args.port)
    print(f"违规线索分流处置服务已启动：http://{args.host}:{args.port}（数据库：{args.db}）")
    print("演示账号见 GET /actors；接口一览见 GET /。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
