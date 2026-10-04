"""SQLite 持久化层。

单连接 + 可重入锁，配合 ThreadingHTTPServer 使用；所有写操作经 tx() 事务提交，
读操作直接查询。业务约束（状态机、租约、权限）在 services 层保证。
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS seq (
  name TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  org_id TEXT
);
CREATE TABLE IF NOT EXISTS subjects (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  name TEXT NOT NULL,
  identifier TEXT NOT NULL UNIQUE,
  org_id TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clues (
  id TEXT PRIMARY KEY,
  channel TEXT NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  event_date TEXT,
  location TEXT,
  reporter_name TEXT,
  reporter_contact_hash TEXT,
  anonymous INTEGER NOT NULL DEFAULT 0,
  fingerprint TEXT NOT NULL,
  tokens TEXT NOT NULL,
  status TEXT NOT NULL,
  case_id TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_clues_case ON clues(case_id);
CREATE INDEX IF NOT EXISTS idx_clues_fingerprint ON clues(fingerprint);
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  state TEXT NOT NULL,
  priority TEXT NOT NULL,
  priority_status TEXT NOT NULL,
  rule_version INTEGER NOT NULL,
  assignee_id TEXT,
  org_id TEXT,
  decision TEXT,
  registered_at TEXT NOT NULL,
  cycle_started_at TEXT NOT NULL,
  due_at TEXT NOT NULL,
  decided_at TEXT,
  archived_at TEXT,
  reopened_count INTEGER NOT NULL DEFAULT 0,
  extension_count INTEGER NOT NULL DEFAULT 0,
  extension_days INTEGER NOT NULL DEFAULT 0,
  parent_id TEXT,
  lease_holder TEXT,
  lease_token TEXT,
  lease_fencing INTEGER NOT NULL DEFAULT 0,
  lease_expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_state ON cases(state);
CREATE TABLE IF NOT EXISTS case_subjects (
  case_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  PRIMARY KEY (case_id, subject_id)
);
CREATE TABLE IF NOT EXISTS case_clues (
  case_id TEXT NOT NULL,
  clue_id TEXT NOT NULL UNIQUE,
  linked_at TEXT NOT NULL,
  PRIMARY KEY (case_id, clue_id)
);
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  filename TEXT,
  content TEXT NOT NULL,
  sensitivity INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  uploaded_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE TABLE IF NOT EXISTS merge_suggestions (
  id TEXT PRIMARY KEY,
  clue_id TEXT NOT NULL,
  source_case_id TEXT NOT NULL,
  target_case_id TEXT NOT NULL,
  score REAL NOT NULL,
  signals TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  decided_by TEXT,
  decided_at TEXT,
  decision_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_merge_status ON merge_suggestions(status);
CREATE TABLE IF NOT EXISTS priority_assessments (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  rule_version INTEGER NOT NULL,
  score INTEGER NOT NULL,
  suggested_level TEXT NOT NULL,
  hits TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  confirmed_by TEXT,
  confirmed_level TEXT,
  decided_at TEXT,
  reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_assess_case ON priority_assessments(case_id);
CREATE TABLE IF NOT EXISTS risk_rules (
  id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  params TEXT NOT NULL,
  points INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS extensions (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  days INTEGER NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  decided_by TEXT,
  decided_at TEXT,
  decision_reason TEXT
);
CREATE TABLE IF NOT EXISTS measures (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  type TEXT NOT NULL,
  note TEXT,
  status TEXT NOT NULL,
  imposed_by TEXT NOT NULL,
  imposed_at TEXT NOT NULL,
  lifted_by TEXT,
  lifted_at TEXT,
  lift_reason TEXT
);
CREATE TABLE IF NOT EXISTS audits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_role TEXT NOT NULL,
  action TEXT NOT NULL,
  reason TEXT,
  detail TEXT,
  from_state TEXT,
  to_state TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audits_case ON audits(case_id);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.isolation_level = None  # 手动事务
        self.lock = threading.RLock()
        with self.lock:
            self.conn.executescript(_SCHEMA)

    @contextmanager
    def tx(self):
        """写事务：服务层每个变更操作开启一个，禁止嵌套。"""
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    # ---- 基础读写 ----
    def one(self, sql: str, args: tuple = ()) -> dict | None:
        with self.lock:
            row = self.conn.execute(sql, args).fetchone()
        return dict(row) if row else None

    def all(self, sql: str, args: tuple = ()) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    def execute(self, sql: str, args: tuple = ()) -> None:
        with self.lock:
            self.conn.execute(sql, args)

    def next_id(self, prefix: str) -> str:
        """在事务内发号，格式如 CLU-000001。"""
        row = self.one("SELECT value FROM seq WHERE name=?", (prefix,))
        if row is None:
            self.execute("INSERT INTO seq(name, value) VALUES (?, 1)", (prefix,))
            value = 1
        else:
            value = int(row["value"]) + 1
            self.execute("UPDATE seq SET value=? WHERE name=?", (value, prefix))
        return f"{prefix}-{value:06d}"

    # ---- 元数据 ----
    def get_meta(self, key: str) -> str | None:
        row = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)


def loads(text: str):
    return json.loads(text)
