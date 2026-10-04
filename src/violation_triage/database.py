"""SQLite 连接与建表脚本。

所有写操作在服务层用单连接事务包裹；开启 WAL 以支持读写并发。
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- 处置人员账号
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    role          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT NOT NULL
);

-- 风险规则（版本化，不可变：每次发布写新版本）
CREATE TABLE IF NOT EXISTS risk_rule_versions (
    version     INTEGER PRIMARY KEY,
    published_by INTEGER REFERENCES users(id),
    published_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    note        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS risk_rules (
    id          INTEGER PRIMARY KEY,
    version     INTEGER NOT NULL REFERENCES risk_rule_versions(version),
    rule_key    TEXT NOT NULL,
    title       TEXT NOT NULL,
    condition   TEXT NOT NULL,            -- JSON 条件表达式，见 risk.py
    add_score   INTEGER NOT NULL,
    suggest_priority TEXT,                -- 命中后建议的优先级（可空）
    UNIQUE (version, rule_key)
);

-- 线索主体（去重锚点：统一社会信用代码 / 证件号）
CREATE TABLE IF NOT EXISTS subjects (
    id          INTEGER PRIMARY KEY,
    subject_type TEXT NOT NULL,           -- 机构 / 人员
    name        TEXT NOT NULL,
    identifier  TEXT NOT NULL UNIQUE,     -- 统一社会信用代码或身份证号（密文/原文由部署决定）
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- 线索
CREATE TABLE IF NOT EXISTS clues (
    id              INTEGER PRIMARY KEY,
    clue_no         TEXT NOT NULL UNIQUE,
    source_channel  TEXT NOT NULL,         -- 投诉 / 巡查 / 机构自报
    source_ref      TEXT NOT NULL DEFAULT '',
    fingerprint     TEXT NOT NULL,         -- 来源指纹（规范化哈希）
    fingerprint_norm TEXT NOT NULL,        -- 规范化指纹原文（用于跨渠道比对）
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    occurrence_at   TEXT,
    region          TEXT NOT NULL DEFAULT '',

    subject_id      INTEGER REFERENCES subjects(id),
    reporter_contact TEXT NOT NULL DEFAULT '',  -- 可能含举报人个人信息，按敏感字段处理

    state           TEXT NOT NULL DEFAULT '登记',
    priority        TEXT,                  -- 已确认优先级（NULL=未确认）
    suggested_priority TEXT,               -- 系统建议优先级
    priority_reason TEXT NOT NULL DEFAULT '',
    rule_version    INTEGER,               -- 评分时使用的规则版本

    risk_score      INTEGER NOT NULL DEFAULT 0,
    risk_hits       TEXT NOT NULL DEFAULT '[]',  -- 命中规则明细 JSON
    due_at          TEXT,                  -- 办理时限
    deadline_extensions TEXT NOT NULL DEFAULT '[]', -- 延期记录 JSON

    merged_into     INTEGER REFERENCES clues(id),
    parent_id       INTEGER REFERENCES clues(id),
    created_by      INTEGER REFERENCES users(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_clues_state ON clues(state);
CREATE INDEX IF NOT EXISTS idx_clues_subject ON clues(subject_id);
CREATE INDEX IF NOT EXISTS idx_clues_fp ON clues(fingerprint_norm);
CREATE INDEX IF NOT EXISTS idx_clues_merged ON clues(merged_into);

-- 证据（敏感度分级，按角色裁剪）
CREATE TABLE IF NOT EXISTS evidences (
    id           INTEGER PRIMARY KEY,
    clue_id      INTEGER NOT NULL REFERENCES clues(id),
    label        TEXT NOT NULL,
    content_ref  TEXT NOT NULL,            -- 存储位置/摘要，不直接回显机密内容
    sensitivity  TEXT NOT NULL,            -- 普通/内部/敏感/机密
    kind         TEXT NOT NULL DEFAULT '文档',
    uploaded_by  INTEGER REFERENCES users(id),
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_clue ON evidences(clue_id);

-- 合并建议（人工确认）
CREATE TABLE IF NOT EXISTS merge_suggestions (
    id           INTEGER PRIMARY KEY,
    primary_clue_id  INTEGER NOT NULL REFERENCES clues(id),
    duplicate_clue_id INTEGER NOT NULL REFERENCES clues(id),
    score        REAL NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT '待确认',  -- 待确认/已确认/已驳回
    decided_by   INTEGER REFERENCES users(id),
    decided_at   TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (primary_clue_id, duplicate_clue_id)
);

-- 处置租约
CREATE TABLE IF NOT EXISTS leases (
    clue_id     INTEGER PRIMARY KEY REFERENCES clues(id),
    holder_id   INTEGER NOT NULL REFERENCES users(id),
    holder_name TEXT NOT NULL,
    token       TEXT NOT NULL UNIQUE,
    leased_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at  TEXT NOT NULL
);

-- 临时措施
CREATE TABLE IF NOT EXISTS interim_measures (
    id          INTEGER PRIMARY KEY,
    clue_id     INTEGER NOT NULL REFERENCES clues(id),
    measure_type TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '生效中',  -- 生效中/已解除
    created_by  INTEGER REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    lifted_by   INTEGER REFERENCES users(id),
    lifted_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_measure_clue ON interim_measures(clue_id);

-- 延期审批
CREATE TABLE IF NOT EXISTS extensions (
    id          INTEGER PRIMARY KEY,
    clue_id     INTEGER NOT NULL REFERENCES clues(id),
    hours       INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT '待审批',  -- 待审批/已批准/已驳回
    requested_by INTEGER REFERENCES users(id),
    decided_by  INTEGER REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    decided_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_extension_clue ON extensions(clue_id);

-- 分流/处置动作审计轨迹（追加写）
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY,
    clue_id     INTEGER REFERENCES clues(id),
    actor_id    INTEGER REFERENCES users(id),
    actor_name  TEXT NOT NULL,
    actor_role  TEXT NOT NULL,
    action      TEXT NOT NULL,
    from_state  TEXT,
    to_state    TEXT,
    reason      TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_clue ON audit_logs(clue_id);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
