"""启动违规线索分流处置服务端。

用法：python3 tools/run_server.py [--host H] [--port P] [--db PATH]
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from clueflow.__main__ import main

if __name__ == "__main__":
    main()
