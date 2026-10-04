"""领域服务：线索登记、合并/优先级建议、租约、状态机、措施、延期、审计。"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import timedelta

from . import risk
from .config import (
    DEFAULT_DEADLINE_HOURS,
    PERMISSIONS,
    PRIORITIES,
    PRIORITY_RANK,
    ROLE_MAX_SENSITIVITY,
    SENSITIVITY_LEVELS,
    STATE_ARCHIVED,
    STATE_DECIDED,
    STATE_PENDING_VERIFY,
    STATE_PROCESSING,
    STATE_REGISTERED,
)
from .database import connect, init_db
from .errors import (
    AuthError,
    ConflictError,
    NotFoundError,
    PermissionError,
    ValidationError,
)
from .security import hash_password, new_token, verify_password
from .timeutil import now, now_str, parse, plus_hours, plus_seconds, ts_str

# 合法状态迁移（合并归档、拆分为特例，单独处理）。
TRANSITIONS: dict[str, tuple[str, ...]] = {
    "clue.accept": (STATE_REGISTERED, STATE_PENDING_VERIFY),
    "clue.verify": (STATE_PENDING_VERIFY, STATE_PROCESSING),
    "clue.close": (STATE_PROCESSING, STATE_DECIDED),
    "clue.archive": (STATE_DECIDED, STATE_ARCHIVED),
    "clue.reopen": (STATE_ARCHIVED, STATE_PROCESSING),
}

CLOSE_DECISIONS = ("属实立案", "不予立案", "责令整改", "移送司法", "驳回投诉")
OPEN_STATES = (STATE_REGISTERED, STATE_PENDING_VERIFY, STATE_PROCESSING)
SENS_RANK = {name: i for i, name in enumerate(SENSITIVITY_LEVELS)}

_PUNCT_RE = re.compile(r"[\s　，。、；：？！,.;:!?（）()【】\[\]\"'`~@#$%^&*_+\-=|/<>《》]+")


def _normalize_text(text: str) -> str:
    return _PUNCT_RE.sub("", (text or "").lower())


def _shingles(text: str, size: int = 2) -> set[str]:
    compact = _normalize_text(text)
    if len(compact) <= size:
        return {compact} if compact else set()
    return {compact[i : i + size] for i in range(len(compact) - size + 1)}


def make_fingerprint(
    source_channel: str,
    source_ref: str,
    subject_identifier: str,
    occurrence_at: str | None,
    title: str,
) -> tuple[str, str]:
    """生成来源指纹：返回 (sha256, 规范化原文)。

    同渠道同文号/同主体同发生日且标题高度相同时视为同源。
    """
    occurrence_day = (occurrence_at or "")[:10]
    parts = [
        source_channel.strip(),
        (source_ref or "").strip().lower(),
        (subject_identifier or "").strip().upper(),
        occurrence_day,
        _normalize_text(title)[:80],
    ]
    norm = "|".join(parts)
    import hashlib

    return hashlib.sha256(norm.encode("utf-8")).hexdigest(), norm


class TriageService:
    def __init__(self, db_path: str, lease_seconds: int = 1800) -> None:
        self.db_path = db_path
        self.lease_seconds = lease_seconds
        # 建表并持久化 WAL 模式；每个工作线程使用各自的连接。
        bootstrap = connect(db_path)
        init_db(bootstrap)
        bootstrap.close()
        self._local = threading.local()

    @property
    def conn(self) -> sqlite3.Connection:
        """线程本地连接：SQLite 连接不能跨线程共享。"""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = connect(self.db_path)
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # ---- 基础工具 ----------------------------------------------------------

    @contextmanager
    def _tx(self) -> "sqlite3.Connection":
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def _audit(
        self,
        conn: sqlite3.Connection,
        *,
        actor: sqlite3.Row | None,
        action: str,
        clue_id: int | None = None,
        from_state: str | None = None,
        to_state: str | None = None,
        reason: str = "",
        detail: dict | None = None,
    ) -> None:
        conn.execute(
            """INSERT INTO audit_logs
               (clue_id, actor_id, actor_name, actor_role, action, from_state, to_state, reason, detail_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                clue_id,
                actor["id"] if actor else None,
                actor["display_name"] if actor else "系统",
                actor["role"] if actor else "系统",
                action,
                from_state,
                to_state,
                reason,
                json.dumps(detail or {}, ensure_ascii=False),
            ),
        )

    def require(self, action: str, user: sqlite3.Row) -> None:
        if user["role"] not in PERMISSIONS.get(action, frozenset()):
            raise PermissionError(f"角色 {user['role']} 无权执行 {action}", details={"action": action})

    def _get_clue(self, conn: sqlite3.Connection, ref: str | int) -> sqlite3.Row:
        if isinstance(ref, int) or (isinstance(ref, str) and ref.isdigit()):
            row = conn.execute("SELECT * FROM clues WHERE id = ?", (int(ref),)).fetchone()
        else:
            row = conn.execute("SELECT * FROM clues WHERE clue_no = ?", (ref,)).fetchone()
        if row is None:
            raise NotFoundError("线索不存在", details={"clue": str(ref)})
        return row

    def _get_user(self, conn: sqlite3.Connection, user_id: int) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise NotFoundError("处置人员不存在", details={"user_id": user_id})
        return row

    def _purge_expired_leases(self, conn: sqlite3.Connection) -> None:
        conn.execute("DELETE FROM leases WHERE expires_at <= ?", (now_str(),))

    def _active_lease(self, conn: sqlite3.Connection, clue_id: int) -> sqlite3.Row | None:
        self._purge_expired_leases(conn)
        return conn.execute("SELECT * FROM leases WHERE clue_id = ?", (clue_id,)).fetchone()

    def _set_state(self, conn, row: sqlite3.Row, new_state: str) -> None:
        conn.execute(
            "UPDATE clues SET state = ?, updated_at = ? WHERE id = ?",
            (new_state, now_str(), row["id"]),
        )

    def _check_transition(self, action: str, current: str) -> None:
        allowed_from, expected_to = TRANSITIONS[action]
        if current != allowed_from:
            raise ConflictError(
                f"当前状态为「{current}」，不能执行该动作（仅「{allowed_from}」可执行）",
                details={"current_state": current, "required_state": allowed_from},
            )

    def _latest_rule_version(self, conn: sqlite3.Connection) -> int | None:
        row = conn.execute("SELECT MAX(version) AS v FROM risk_rule_versions").fetchone()
        return row["v"]

    # ---- 用户与会话 --------------------------------------------------------

    def create_user(self, username: str, password: str, display_name: str, role: str) -> dict:
        if role not in ROLE_MAX_SENSITIVITY:
            raise ValidationError("未知角色", details={"role": role})
        if not username or not password:
            raise ValidationError("用户名和密码不能为空")
        try:
            with self._tx() as conn:
                cur = conn.execute(
                    "INSERT INTO users (username, display_name, role, password_hash) VALUES (?, ?, ?, ?)",
                    (username, display_name, role, hash_password(password)),
                )
                self._audit(conn, actor=None, action="user.create", detail={"username": username, "role": role})
                return {"id": cur.lastrowid, "username": username, "display_name": display_name, "role": role}
        except sqlite3.IntegrityError:
            raise ConflictError("用户名已存在", details={"username": username})

    def login(self, username: str, password: str) -> dict:
        row = self.conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None or not verify_password(password, row["password_hash"]):
            raise AuthError("用户名或密码错误")
        token = new_token()
        expires = plus_hours(now(), 12)
        self.conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, row["id"], expires),
        )
        self.conn.commit()
        return {
            "token": token,
            "expires_at": expires,
            "user": {"id": row["id"], "username": row["username"], "display_name": row["display_name"], "role": row["role"]},
        }

    def logout(self, token: str) -> None:
        self.conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        self.conn.commit()

    def authenticate(self, token: str | None) -> sqlite3.Row:
        if not token:
            raise AuthError("缺少会话令牌")
        row = self.conn.execute(
            """SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token = ? AND s.expires_at > ?""",
            (token, now_str()),
        ).fetchone()
        if row is None:
            raise AuthError("会话不存在或已过期")
        return row

    # ---- 风险规则版本 ------------------------------------------------------

    def publish_rules(self, actor: sqlite3.Row, rules: list[dict], note: str = "") -> dict:
        self.require("rules.publish", actor)
        if not rules:
            raise ValidationError("规则列表不能为空")
        cleaned: list[dict] = []
        for item in rules:
            for key in ("rule_key", "title", "condition", "add_score"):
                if key not in item:
                    raise ValidationError(f"规则缺少字段 {key}")
            if not isinstance(item["condition"], dict):
                raise ValidationError("condition 必须是对象")
            # 试求值一次，验证结构合法
            risk.evaluate(item["condition"], {})
            priority = item.get("suggest_priority")
            if priority is not None and priority not in PRIORITIES:
                raise ValidationError("未知建议优先级", details={"priority": priority})
            score = int(item["add_score"])
            if score < 0:
                raise ValidationError("add_score 不能为负")
            cleaned.append(
                {
                    "rule_key": str(item["rule_key"]),
                    "title": str(item["title"]),
                    "condition": json.dumps(item["condition"], ensure_ascii=False),
                    "add_score": score,
                    "suggest_priority": priority,
                }
            )
        keys = [c["rule_key"] for c in cleaned]
        if len(keys) != len(set(keys)):
            raise ValidationError("同版本内 rule_key 不能重复")
        with self._tx() as conn:
            version = (self._latest_rule_version(conn) or 0) + 1
            conn.execute(
                "INSERT INTO risk_rule_versions (version, published_by, note) VALUES (?, ?, ?)",
                (version, actor["id"], note),
            )
            conn.executemany(
                """INSERT INTO risk_rules (version, rule_key, title, condition, add_score, suggest_priority)
                   VALUES (:version, :rule_key, :title, :condition, :add_score, :suggest_priority)""",
                [{**c, "version": version} for c in cleaned],
            )
            self._audit(conn, actor=actor, action="rules.publish", reason=note, detail={"version": version, "rule_count": len(cleaned)})
        return {"version": version, "rule_count": len(cleaned)}

    def list_rule_versions(self, user: sqlite3.Row) -> list[dict]:
        rows = self.conn.execute(
            """SELECT v.*, u.display_name AS published_by_name,
                      (SELECT COUNT(*) FROM risk_rules r WHERE r.version = v.version) AS rule_count
               FROM risk_rule_versions v LEFT JOIN users u ON u.id = v.published_by
               ORDER BY v.version DESC"""
        ).fetchall()
        return [dict(v) for v in rows]

    def get_rules(self, version: int | None = None) -> dict:
        conn = self.conn
        version = version or self._latest_rule_version(conn)
        if version is None:
            return {"version": None, "rules": []}
        vrow = conn.execute("SELECT * FROM risk_rule_versions WHERE version = ?", (version,)).fetchone()
        if vrow is None:
            raise NotFoundError("规则版本不存在", details={"version": version})
        rules = [
            {
                "rule_key": r["rule_key"],
                "title": r["title"],
                "condition": json.loads(r["condition"]),
                "add_score": r["add_score"],
                "suggest_priority": r["suggest_priority"],
            }
            for r in conn.execute("SELECT * FROM risk_rules WHERE version = ? ORDER BY id", (version,)).fetchall()
        ]
        return {"version": version, "note": vrow["note"], "rules": rules}

    # ---- 主体 --------------------------------------------------------------

    def _get_or_create_subject(self, conn: sqlite3.Connection, payload: dict) -> int:
        subject_type = payload.get("subject_type", "")
        name = (payload.get("subject_name") or "").strip()
        identifier = (payload.get("subject_identifier") or "").strip().upper()
        if subject_type not in ("机构", "人员"):
            raise ValidationError("subject_type 必须是 机构/人员")
        if not name or not identifier:
            raise ValidationError("涉及主体名称与证件代码不能为空")
        row = conn.execute("SELECT * FROM subjects WHERE identifier = ?", (identifier,)).fetchone()
        if row is not None:
            return row["id"]
        cur = conn.execute(
            "INSERT INTO subjects (subject_type, name, identifier) VALUES (?, ?, ?)",
            (subject_type, name, identifier),
        )
        return cur.lastrowid

    # ---- 评分与重复发现 ----------------------------------------------------

    def _facts(self, conn: sqlite3.Connection, clue: sqlite3.Row) -> dict:
        sens = [
            r["sensitivity"]
            for r in conn.execute("SELECT sensitivity FROM evidences WHERE clue_id = ?", (clue["id"],)).fetchall()
        ]
        evidence_count = conn.execute("SELECT COUNT(*) AS c FROM evidences WHERE clue_id = ?", (clue["id"],)).fetchone()["c"]
        return {
            "source_channel": clue["source_channel"],
            "title_desc": f"{clue['title']}\n{clue['description']}",
            "subject_type": conn.execute("SELECT subject_type FROM subjects WHERE id = ?", (clue["subject_id"],)).fetchone()["subject_type"],
            "region": clue["region"],
            "has_sensitive_evidence": any(SENS_RANK[s] >= SENS_RANK["敏感"] for s in sens),
            "evidence_count": evidence_count,
        }

    def _score_clue(self, conn: sqlite3.Connection, clue: sqlite3.Row) -> dict:
        version = self._latest_rule_version(conn)
        if version is None:
            result = {"risk_score": 0, "suggested_priority": "低", "risk_hits": []}
        else:
            rules = conn.execute("SELECT * FROM risk_rules WHERE version = ?", (version,)).fetchall()
            result = risk.evaluate_rules(rules, self._facts(conn, clue))
        conn.execute(
            "UPDATE clues SET risk_score = ?, suggested_priority = ?, risk_hits = ?, rule_version = ?, updated_at = ? WHERE id = ?",
            (
                result["risk_score"],
                result["suggested_priority"],
                json.dumps(result["risk_hits"], ensure_ascii=False),
                version,
                now_str(),
                clue["id"],
            ),
        )
        return result

    def _dup_candidates(self, conn: sqlite3.Connection, clue: sqlite3.Row) -> list[dict]:
        """同主体、未合并、在办线索之间计算相似度。"""
        title_shingles = _shingles(clue["title"])
        day = (clue["occurrence_at"] or "")[:10]
        rows = conn.execute(
            """SELECT * FROM clues
               WHERE subject_id = ? AND id != ? AND merged_into IS NULL AND state != '已归档'
               ORDER BY created_at DESC LIMIT 200""",
            (clue["subject_id"], clue["id"]),
        ).fetchall()
        candidates: list[dict] = []
        for other in rows:
            score = 0.0
            reasons: list[str] = []
            if day and (other["occurrence_at"] or "")[:10] == day:
                score += 0.6
                reasons.append("发生日期相同")
            other_shingles = _shingles(other["title"])
            if title_shingles and other_shingles:
                overlap = len(title_shingles & other_shingles) / len(title_shingles | other_shingles)
                score += round(overlap, 3)
                if overlap >= 0.3:
                    reasons.append(f"标题相似度 {overlap:.0%}")
            if clue["source_channel"] == other["source_channel"]:
                score += 0.05
            if clue["region"] and clue["region"] == other["region"]:
                score += 0.1
                reasons.append("同辖区")
            if clue["source_ref"] and clue["source_ref"].strip() == other["source_ref"].strip():
                score += 0.4
                reasons.append("来源文号一致")
            if score >= 0.45:
                candidates.append(
                    {
                        "other": other,
                        "score": round(min(score, 1.0), 3),
                        "reason": "、".join(reasons) or "同主体高度关联",
                    }
                )
        candidates.sort(key=lambda c: c["score"], reverse=True)
        return candidates[:5]

    def _create_merge_suggestions(self, conn: sqlite3.Connection, clue: sqlite3.Row) -> list[dict]:
        created: list[dict] = []
        for cand in self._dup_candidates(conn, clue):
            other = cand["other"]
            # 主线索取更早登记的一条
            primary, duplicate = (other, clue) if other["created_at"] <= clue["created_at"] else (clue, other)
            exists = conn.execute(
                "SELECT 1 FROM merge_suggestions WHERE primary_clue_id = ? AND duplicate_clue_id = ?",
                (primary["id"], duplicate["id"]),
            ).fetchone()
            if exists:
                continue
            conn.execute(
                """INSERT INTO merge_suggestions (primary_clue_id, duplicate_clue_id, score, reason)
                   VALUES (?, ?, ?, ?)""",
                (primary["id"], duplicate["id"], cand["score"], cand["reason"]),
            )
            created.append({"primary_id": primary["id"], "duplicate_id": duplicate["id"], "score": cand["score"], "reason": cand["reason"]})
        return created

    # ---- 登记 --------------------------------------------------------------

    def register_clue(self, actor: sqlite3.Row, payload: dict) -> dict:
        self.require("clue.create", actor)
        channel = (payload.get("source_channel") or "").strip()
        if channel not in ("投诉", "巡查", "机构自报"):
            raise ValidationError("source_channel 必须是 投诉/巡查/机构自报")
        title = (payload.get("title") or "").strip()
        if not title:
            raise ValidationError("标题不能为空")
        source_ref = (payload.get("source_ref") or "").strip()
        occurrence_at = payload.get("occurrence_at") or None
        if occurrence_at:
            try:
                parse(occurrence_at)
            except ValueError:
                raise ValidationError("occurrence_at 时间格式非法（应为 ISO 8601）")

        with self._tx() as conn:
            subject_id = self._get_or_create_subject(conn, payload)
            identifier = conn.execute("SELECT identifier FROM subjects WHERE id = ?", (subject_id,)).fetchone()["identifier"]
            fp, fp_norm = make_fingerprint(channel, source_ref, identifier, occurrence_at, title)

            # 完全同指纹：幂等返回既有线索（同渠道重复推送/登记）。
            existing = conn.execute("SELECT * FROM clues WHERE fingerprint = ?", (fp,)).fetchone()
            if existing is not None:
                self._audit(
                    conn, actor=actor, action="clue.register_duplicate", clue_id=existing["id"],
                    reason="来源指纹完全一致，按重复登记幂等处理",
                    detail={"fingerprint": fp, "channel": channel},
                )
                return {"duplicate": True, "clue_id": existing["id"], "clue_no": existing["clue_no"]}

            today = now().strftime("%Y%m%d")
            seq = conn.execute("SELECT COUNT(*) AS c FROM clues").fetchone()["c"] + 1
            clue_no = f"XS-{today}-{seq:04d}"
            cur = conn.execute(
                """INSERT INTO clues
                   (clue_no, source_channel, source_ref, fingerprint, fingerprint_norm, title, description,
                    occurrence_at, region, subject_id, reporter_contact, created_by, state)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    clue_no, channel, source_ref, fp, fp_norm, title,
                    payload.get("description", ""), occurrence_at, payload.get("region", ""),
                    subject_id, payload.get("reporter_contact", ""), actor["id"], STATE_REGISTERED,
                ),
            )
            clue_id = cur.lastrowid
            row = self._get_clue(conn, clue_id)

            evidences = payload.get("evidences") or []
            for ev in evidences:
                self._insert_evidence(conn, actor, clue_id, ev)

            scored = self._score_clue(conn, row)
            row = self._get_clue(conn, clue_id)
            suggestions = self._create_merge_suggestions(conn, row)
            self._audit(
                conn, actor=actor, action="clue.register", clue_id=clue_id,
                to_state=STATE_REGISTERED,
                reason=f"{channel}渠道登记：{title}",
                detail={
                    "fingerprint": fp,
                    "risk_score": scored["risk_score"],
                    "suggested_priority": scored["suggested_priority"],
                    "merge_candidates": suggestions,
                },
            )
            return {
                "duplicate": False,
                "clue_id": clue_id,
                "clue_no": clue_no,
                "risk_score": scored["risk_score"],
                "suggested_priority": scored["suggested_priority"],
                "risk_hits": scored["risk_hits"],
                "merge_suggestions": suggestions,
            }

    # ---- 查询 --------------------------------------------------------------

    def list_clues(self, user: sqlite3.Row, params: dict) -> dict:
        sql = "SELECT * FROM clues WHERE 1=1"
        args: list = []
        if params.get("state"):
            states = params["state"].split(",")
            sql += f" AND state IN ({','.join('?' * len(states))})"
            args.extend(states)
        if params.get("priority"):
            sql += " AND priority = ?"
            args.append(params["priority"])
        if params.get("source_channel"):
            sql += " AND source_channel = ?"
            args.append(params["source_channel"])
        if params.get("subject_identifier"):
            sql += " AND subject_id = (SELECT id FROM subjects WHERE identifier = ?)"
            args.append(params["subject_identifier"].strip().upper())
        if params.get("q"):
            sql += " AND (title LIKE ? OR clue_no LIKE ? OR description LIKE ?)"
            kw = f"%{params['q']}%"
            args.extend([kw, kw, kw])
        include_merged = params.get("include_merged") in ("1", "true", "yes")
        if not include_merged:
            sql += " AND merged_into IS NULL"
        if params.get("overdue") in ("1", "true", "yes"):
            sql += " AND due_at IS NOT NULL AND due_at < ? AND state IN ('登记','待核验','处置中')"
            args.append(now_str())
        if params.get("mine") in ("1", "true", "yes"):
            sql += " AND id IN (SELECT clue_id FROM leases WHERE holder_id = ? AND expires_at > ?)"
            args.extend([user["id"], now_str()])

        order_priority = "CASE priority WHEN '特急' THEN 0 WHEN '紧急' THEN 1 WHEN '高' THEN 2 WHEN '中' THEN 3 ELSE 4 END"
        sql += f" ORDER BY (due_at IS NOT NULL AND due_at < ? AND state IN ('登记','待核验','处置中')) DESC, {order_priority}, due_at IS NULL, due_at ASC, id DESC"
        args.append(now_str())

        limit = min(int(params.get("limit", 50)), 200)
        offset = int(params.get("offset", 0))
        rows = self.conn.execute(sql + f" LIMIT {limit} OFFSET {offset}", args).fetchall()
        total = self.conn.execute("SELECT COUNT(*) AS c FROM (" + sql + ")", args).fetchone()["c"]
        return {"total": total, "limit": limit, "offset": offset, "items": [self._clue_summary(r) for r in rows]}

    def _clue_summary(self, row: sqlite3.Row) -> dict:
        due = parse(row["due_at"])
        overdue = bool(due and due < now() and row["state"] in OPEN_STATES)
        return {
            "clue_id": row["id"],
            "clue_no": row["clue_no"],
            "title": row["title"],
            "source_channel": row["source_channel"],
            "state": row["state"],
            "priority": row["priority"],
            "suggested_priority": row["suggested_priority"],
            "risk_score": row["risk_score"],
            "due_at": row["due_at"],
            "overdue": overdue,
            "merged_into": row["merged_into"],
            "created_at": row["created_at"],
        }

    # ---- 合并建议 ----------------------------------------------------------

    def list_merge_suggestions(self, user: sqlite3.Row, status: str = "待确认") -> list[dict]:
        self.require("merge.suggest", user)
        rows = self.conn.execute(
            """SELECT m.*, p.clue_no AS primary_clue_no, p.title AS primary_title,
                      d.clue_no AS duplicate_clue_no, d.title AS duplicate_title,
                      u.display_name AS decided_by_name
               FROM merge_suggestions m
               JOIN clues p ON p.id = m.primary_clue_id
               JOIN clues d ON d.id = m.duplicate_clue_id
               LEFT JOIN users u ON u.id = m.decided_by
               WHERE m.status = ? ORDER BY m.score DESC, m.id DESC""",
            (status,),
        ).fetchall()
        return [dict(r) for r in rows]

    def _get_suggestion(self, conn, suggestion_id: int) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM merge_suggestions WHERE id = ?", (suggestion_id,)).fetchone()
        if row is None:
            raise NotFoundError("合并建议不存在", details={"suggestion_id": suggestion_id})
        return row

    def confirm_merge(self, user: sqlite3.Row, suggestion_id: int, reason: str = "") -> dict:
        self.require("merge.confirm", user)
        with self._tx() as conn:
            sug = self._get_suggestion(conn, suggestion_id)
            if sug["status"] != "待确认":
                raise ConflictError("该建议已处理", details={"status": sug["status"]})
            primary = self._get_clue(conn, sug["primary_clue_id"])
            duplicate = self._get_clue(conn, sug["duplicate_clue_id"])
            if primary["merged_into"] is not None or duplicate["merged_into"] is not None:
                raise ConflictError("涉及线索已被合并，不能重复合并")
            if primary["state"] == STATE_ARCHIVED or duplicate["state"] == STATE_ARCHIVED:
                raise ConflictError("已归档线索不能合并")
            if primary["state"] == STATE_DECIDED or duplicate["state"] == STATE_DECIDED:
                raise ConflictError("已作决定的线索不能合并，请先复开")

            # 重复线索释放租约并归入主线索，状态归档为「合并归档」。
            lease = self._active_lease(conn, duplicate["id"])
            conn.execute("DELETE FROM leases WHERE clue_id = ?", (duplicate["id"],))
            conn.execute(
                "UPDATE clues SET merged_into = ?, state = ?, updated_at = ? WHERE id = ?",
                (primary["id"], STATE_ARCHIVED, now_str(), duplicate["id"]),
            )
            conn.execute(
                "UPDATE merge_suggestions SET status = '已确认', decided_by = ?, decided_at = ? WHERE id = ?",
                (user["id"], now_str(), suggestion_id),
            )
            # 该重复线索上的其他待确认建议一并驳回，避免悬挂建议。
            conn.execute(
                """UPDATE merge_suggestions SET status = '已驳回', decided_by = ?, decided_at = ?
                   WHERE status = '待确认' AND id != ? AND (primary_clue_id = ? OR duplicate_clue_id = ?)""",
                (user["id"], now_str(), suggestion_id, duplicate["id"], duplicate["id"]),
            )
            self._audit(
                conn, actor=user, action="merge.confirm", clue_id=primary["id"],
                from_state=duplicate["state"], to_state=STATE_ARCHIVED,
                reason=reason or sug["reason"],
                detail={
                    "primary_clue_no": primary["clue_no"],
                    "duplicate_clue_no": duplicate["clue_no"],
                    "lease_released": lease["holder_name"] if lease else None,
                },
            )
            return {"primary_clue_id": primary["id"], "merged_clue_id": duplicate["id"]}

    def reject_merge(self, user: sqlite3.Row, suggestion_id: int, reason: str = "") -> dict:
        self.require("merge.reject", user)
        with self._tx() as conn:
            sug = self._get_suggestion(conn, suggestion_id)
            if sug["status"] != "待确认":
                raise ConflictError("该建议已处理")
            conn.execute(
                "UPDATE merge_suggestions SET status = '已驳回', decided_by = ?, decided_at = ? WHERE id = ?",
                (user["id"], now_str(), suggestion_id),
            )
            self._audit(
                conn, actor=user, action="merge.reject", clue_id=sug["primary_clue_id"],
                reason=reason or sug["reason"],
                detail={"suggestion_id": suggestion_id, "duplicate_clue_id": sug["duplicate_clue_id"]},
            )
            return {"suggestion_id": suggestion_id, "status": "已驳回"}

    def rescan_duplicates(self, user: sqlite3.Row, clue_ref: str) -> dict:
        self.require("merge.suggest", user)
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            if row["merged_into"] is not None or row["state"] == STATE_ARCHIVED:
                raise ConflictError("已合并/归档线索不再参与查重")
            created = self._create_merge_suggestions(conn, row)
            self._audit(conn, actor=user, action="merge.suggest", clue_id=row["id"],
                        reason="人工触发跨渠道查重", detail={"created": created})
            return {"clue_id": row["id"], "created": created}

    # ---- 优先级确认 --------------------------------------------------------

    def confirm_priority(self, user: sqlite3.Row, clue_ref: str, priority: str, reason: str = "", deadline_hours: int | None = None) -> dict:
        self.require("priority.confirm", user)
        if priority not in PRIORITIES:
            raise ValidationError("优先级必须是 " + "/".join(PRIORITIES))
        if deadline_hours is not None and deadline_hours <= 0:
            raise ValidationError("办理时限必须为正整数小时")
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            if row["merged_into"] is not None:
                raise ConflictError("该线索已合并归档")
            if row["state"] not in (STATE_REGISTERED, STATE_PENDING_VERIFY):
                raise ConflictError(f"当前状态「{row['state']}」不能确认优先级")
            hours = deadline_hours or DEFAULT_DEADLINE_HOURS[priority]
            # 首次确认按优先级设定办理时限；再次确认沿用既定时限（延期记录继续累计）。
            if row["due_at"] is None:
                due_at = plus_hours(now(), hours)
            else:
                due_at = row["due_at"]
            conn.execute(
                "UPDATE clues SET priority = ?, priority_reason = ?, due_at = ?, updated_at = ? WHERE id = ?",
                (priority, reason, due_at, now_str(), row["id"]),
            )
            old_state = row["state"]
            if old_state == STATE_REGISTERED:
                self._set_state(conn, row, STATE_PENDING_VERIFY)
            self._audit(
                conn, actor=user, action="priority.confirm", clue_id=row["id"],
                from_state=old_state,
                to_state=STATE_PENDING_VERIFY if old_state == STATE_REGISTERED else old_state,
                reason=reason or f"按风险评分 {row['risk_score']} 人工确认",
                detail={"priority": priority, "deadline_hours": hours, "suggested_priority": row["suggested_priority"],
                        "rule_version": row["rule_version"]},
            )
            return {"clue_id": row["id"], "priority": priority, "due_at": due_at, "state": STATE_PENDING_VERIFY}

    def rescale_risk(self, user: sqlite3.Row, clue_ref: str) -> dict:
        self.require("priority.suggest", user)
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            if row["merged_into"] is not None:
                raise ConflictError("已合并线索不再评分")
            result = self._score_clue(conn, row)
            refreshed = self._get_clue(conn, row["id"])
            self._audit(conn, actor=user, action="risk.rescale", clue_id=row["id"],
                        reason="按最新规则版本重新评分",
                        detail={"risk_score": result["risk_score"], "suggested_priority": result["suggested_priority"],
                                "rule_version": refreshed["rule_version"]})
            return {"clue_id": row["id"], **result, "rule_version": refreshed["rule_version"]}

    # ---- 受理/租约 ---------------------------------------------------------

    def accept_clue(self, user: sqlite3.Row, clue_ref: str) -> dict:
        self.require("clue.accept", user)
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            self._check_transition("clue.accept", row["state"])
            self._set_state(conn, row, STATE_PENDING_VERIFY)
            self._audit(conn, actor=user, action="clue.accept", clue_id=row["id"],
                        from_state=STATE_REGISTERED, to_state=STATE_PENDING_VERIFY, reason="受理进入核验")
            return {"clue_id": row["id"], "state": STATE_PENDING_VERIFY}

    def claim(self, user: sqlite3.Row, clue_ref: str) -> dict:
        self.require("clue.claim", user)
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            if row["merged_into"] is not None:
                raise ConflictError("线索已合并")
            if row["state"] not in (STATE_PENDING_VERIFY, STATE_PROCESSING):
                raise ConflictError(f"「{row['state']}」状态不能认领，请先受理并确认优先级")
            lease = self._active_lease(conn, row["id"])
            if lease is not None:
                raise ConflictError(
                    "线索已被他人租约式认领",
                    details={"holder": lease["holder_name"], "expires_at": lease["expires_at"]},
                )
            token = new_token()
            expires_str = plus_seconds(now(), self.lease_seconds)
            conn.execute(
                "INSERT INTO leases (clue_id, holder_id, holder_name, token, expires_at) VALUES (?, ?, ?, ?, ?)",
                (row["id"], user["id"], user["display_name"], token, expires_str),
            )
            self._audit(conn, actor=user, action="clue.claim", clue_id=row["id"],
                        reason=f"认领租约，{self.lease_seconds} 秒内有效", detail={"expires_at": expires_str})
            return {"clue_id": row["id"], "lease_token": token, "holder": user["display_name"], "expires_at": expires_str}

    def renew_lease(self, user: sqlite3.Row, clue_ref: str) -> dict:
        self.require("clue.release", user)
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            lease = self._active_lease(conn, row["id"])
            if lease is None:
                raise ConflictError("租约不存在或已过期，请重新认领")
            if lease["holder_id"] != user["id"] and user["role"] != "分流管理员":
                raise PermissionError("只有持有人或分流管理员可以续租")
            expires_str = plus_seconds(now(), self.lease_seconds)
            conn.execute("UPDATE leases SET expires_at = ? WHERE clue_id = ?", (expires_str, row["id"]))
            self._audit(conn, actor=user, action="clue.renew", clue_id=row["id"], detail={"expires_at": expires_str})
            return {"clue_id": row["id"], "expires_at": expires_str}

    def release_clue(self, user: sqlite3.Row, clue_ref: str, reason: str = "") -> dict:
        self.require("clue.release", user)
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            lease = self._active_lease(conn, row["id"])
            if lease is None:
                raise ConflictError("没有有效租约")
            if lease["holder_id"] != user["id"] and user["role"] not in ("分流管理员", "监管人员"):
                raise PermissionError("不能释放他人租约")
            conn.execute("DELETE FROM leases WHERE clue_id = ?", (row["id"],))
            self._audit(conn, actor=user, action="clue.release", clue_id=row["id"], reason=reason or "主动释放租约",
                        detail={"former_holder": lease["holder_name"]})
            return {"clue_id": row["id"], "released": True}

    def assign(self, user: sqlite3.Row, clue_ref: str, assignee_id: int, reason: str = "") -> dict:
        """分派或转派：无有效租约为分派，有租约为转派。"""
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            if row["merged_into"] is not None:
                raise ConflictError("线索已合并")
            if row["state"] not in (STATE_PENDING_VERIFY, STATE_PROCESSING):
                raise ConflictError(f"「{row['state']}」状态不能分派")
            assignee = self._get_user(conn, assignee_id)
            if assignee["role"] not in ("监管人员", "复核专家", "分流管理员"):
                raise ValidationError("只能分派给监管人员/复核专家/分流管理员")
            current = self._active_lease(conn, row["id"])
            if current is None:
                self.require("clue.assign", user)
                action = "clue.assign"
            else:
                self.require("clue.transfer", user)
                if not reason:
                    raise ValidationError("转派必须填写理由")
                action = "clue.transfer"
            token = new_token()
            expires_str = plus_seconds(now(), self.lease_seconds)
            conn.execute("DELETE FROM leases WHERE clue_id = ?", (row["id"],))
            conn.execute(
                "INSERT INTO leases (clue_id, holder_id, holder_name, token, expires_at) VALUES (?, ?, ?, ?, ?)",
                (row["id"], assignee["id"], assignee["display_name"], token, expires_str),
            )
            self._audit(
                conn, actor=user, action=action, clue_id=row["id"], reason=reason,
                detail={"assignee": assignee["display_name"], "assignee_role": assignee["role"],
                        "former_holder": current["holder_name"] if current else None},
            )
            return {"clue_id": row["id"], "action": "transfer" if current else "assign",
                    "holder": assignee["display_name"], "expires_at": expires_str}

    # ---- 核验/结案 ---------------------------------------------------------

    def verify_clue(self, user: sqlite3.Row, clue_ref: str, note: str = "") -> dict:
        self.require("clue.verify", user)
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            self._check_transition("clue.verify", row["state"])
            lease = self._active_lease(conn, row["id"])
            if lease is None or lease["holder_id"] != user["id"]:
                raise ConflictError("核验通过需由当前租约持有人操作（请先认领）")
            self._set_state(conn, row, STATE_PROCESSING)
            self._audit(conn, actor=user, action="clue.verify", clue_id=row["id"],
                        from_state=STATE_PENDING_VERIFY, to_state=STATE_PROCESSING,
                        reason=note or "核验通过，进入处置")
            return {"clue_id": row["id"], "state": STATE_PROCESSING}

    def close_clue(self, user: sqlite3.Row, clue_ref: str, decision: str, summary: str) -> dict:
        self.require("clue.close", user)
        if decision not in CLOSE_DECISIONS:
            raise ValidationError("决定类型必须是 " + "/".join(CLOSE_DECISIONS))
        if not summary:
            raise ValidationError("结案必须填写处置摘要")
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            self._check_transition("clue.close", row["state"])
            active_measure = conn.execute(
                "SELECT COUNT(*) AS c FROM interim_measures WHERE clue_id = ? AND status = '生效中'", (row["id"],)
            ).fetchone()["c"]
            if active_measure:
                raise ConflictError("存在生效中的临时措施，请先解除再结案")
            pending_ext = conn.execute(
                "SELECT COUNT(*) AS c FROM extensions WHERE clue_id = ? AND status = '待审批'", (row["id"],)
            ).fetchone()["c"]
            if pending_ext:
                raise ConflictError("存在待审批的延期申请，请先处理")
            lease = self._active_lease(conn, row["id"])
            if lease is not None and lease["holder_id"] != user["id"] and user["role"] not in ("分流管理员",):
                raise ConflictError("线索由他人持租约处置中", details={"holder": lease["holder_name"]})
            conn.execute("DELETE FROM leases WHERE clue_id = ?", (row["id"],))
            self._set_state(conn, row, STATE_DECIDED)
            self._audit(
                conn, actor=user, action="clue.close", clue_id=row["id"],
                from_state=STATE_PROCESSING, to_state=STATE_DECIDED,
                reason=f"决定：{decision}；{summary}",
                detail={"decision": decision, "summary": summary},
            )
            return {"clue_id": row["id"], "state": STATE_DECIDED, "decision": decision}

    def archive_clue(self, user: sqlite3.Row, clue_ref: str) -> dict:
        self.require("clue.close", user)
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            self._check_transition("clue.archive", row["state"])
            self._set_state(conn, row, STATE_ARCHIVED)
            self._audit(conn, actor=user, action="clue.archive", clue_id=row["id"],
                        from_state=STATE_DECIDED, to_state=STATE_ARCHIVED, reason="归档")
            return {"clue_id": row["id"], "state": STATE_ARCHIVED}

    def reopen_clue(self, user: sqlite3.Row, clue_ref: str, reason: str) -> dict:
        self.require("clue.reopen", user)
        if not reason:
            raise ValidationError("复开必须填写理由")
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            if row["state"] != STATE_ARCHIVED:
                raise ConflictError("只有已归档线索可以复开")
            if row["merged_into"] is not None:
                raise ConflictError("因合并归档的线索不能复开，请在主线索上继续处置")
            self._check_transition("clue.reopen", row["state"])
            self._set_state(conn, row, STATE_PROCESSING)
            token = new_token()
            expires_str = plus_seconds(now(), self.lease_seconds)
            conn.execute("DELETE FROM leases WHERE clue_id = ?", (row["id"],))
            conn.execute(
                "INSERT INTO leases (clue_id, holder_id, holder_name, token, expires_at) VALUES (?, ?, ?, ?, ?)",
                (row["id"], user["id"], user["display_name"], token, expires_str),
            )
            self._audit(conn, actor=user, action="clue.reopen", clue_id=row["id"],
                        from_state=STATE_ARCHIVED, to_state=STATE_PROCESSING, reason=reason,
                        detail={"lease_expires_at": expires_str})
            return {"clue_id": row["id"], "state": STATE_PROCESSING, "lease_expires_at": expires_str}

    # ---- 拆分 --------------------------------------------------------------

    def split_clue(self, user: sqlite3.Row, clue_ref: str, children: list[dict]) -> dict:
        self.require("clue.split", user)
        if not children:
            raise ValidationError("至少拆分出一条子线索")
        if len(children) > 20:
            raise ValidationError("单次拆分不能超过 20 条")
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            if row["merged_into"] is not None:
                raise ConflictError("已合并线索不能拆分")
            if row["state"] not in (STATE_PENDING_VERIFY, STATE_PROCESSING):
                raise ConflictError(f"「{row['state']}」状态不能拆分")
            lease = self._active_lease(conn, row["id"])
            if lease is not None and lease["holder_id"] != user["id"] and user["role"] not in ("分流管理员", "监管人员"):
                raise ConflictError("线索由他人持租约处置中", details={"holder": lease["holder_name"]})

            today = now().strftime("%Y%m%d")
            created: list[dict] = []
            for child in children:
                title = (child.get("title") or "").strip()
                if not title:
                    raise ValidationError("子线索标题不能为空")
                seq = conn.execute("SELECT COUNT(*) AS c FROM clues").fetchone()["c"] + 1
                cur = conn.execute(
                    """INSERT INTO clues
                       (clue_no, source_channel, source_ref, fingerprint, fingerprint_norm, title, description,
                        occurrence_at, region, subject_id, reporter_contact, state, parent_id,
                        priority, due_at, rule_version, created_by)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        f"XS-{today}-{seq:04d}", row["source_channel"], row["source_ref"],
                        row["fingerprint"], row["fingerprint_norm"], title,
                        child.get("description", row["description"]), row["occurrence_at"], row["region"],
                        row["subject_id"], row["reporter_contact"], STATE_PENDING_VERIFY, row["id"],
                        row["priority"], row["due_at"], row["rule_version"], user["id"],
                    ),
                )
                child_id = cur.lastrowid
                # 复制勾选的证据（保留原证据在母线索上，维持审计完整）。
                for ev_id in child.get("evidence_ids") or []:
                    ev = conn.execute("SELECT * FROM evidences WHERE id = ? AND clue_id = ?", (ev_id, row["id"])).fetchone()
                    if ev is None:
                        raise NotFoundError("待复制证据不存在或不属于母线索", details={"evidence_id": ev_id})
                    conn.execute(
                        """INSERT INTO evidences (clue_id, label, content_ref, sensitivity, kind, uploaded_by)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (child_id, f"[拆分复制] {ev['label']}", ev["content_ref"], ev["sensitivity"], ev["kind"], user["id"]),
                    )
                new_row = self._get_clue(conn, child_id)
                self._score_clue(conn, new_row)
                created.append({"clue_id": child_id, "title": title})
                self._audit(
                    conn, actor=user, action="clue.split", clue_id=child_id, to_state=STATE_PENDING_VERIFY,
                    reason=f"从 {row['clue_no']} 拆分：{title}",
                    detail={"parent_clue_id": row["id"], "parent_clue_no": row["clue_no"]},
                )
            self._audit(conn, actor=user, action="clue.split", clue_id=row["id"],
                        reason=f"拆分出 {len(created)} 条子线索", detail={"children": created})
            return {"parent_clue_id": row["id"], "children": created}

    # ---- 证据 --------------------------------------------------------------

    def _insert_evidence(self, conn: sqlite3.Connection, actor: sqlite3.Row, clue_id: int, payload: dict) -> int:
        label = (payload.get("label") or "").strip()
        content_ref = (payload.get("content_ref") or "").strip()
        sensitivity = payload.get("sensitivity", "普通")
        kind = payload.get("kind", "文档")
        if not label or not content_ref:
            raise ValidationError("证据 label 与 content_ref 不能为空")
        if sensitivity not in SENSITIVITY_LEVELS:
            raise ValidationError("敏感度必须是 " + "/".join(SENSITIVITY_LEVELS))
        # 机构端只能提交普通证据；更高等级由监管端在核验时调整。
        if actor["role"] in ("机构合规员", "执业人员") and sensitivity != "普通":
            raise PermissionError("机构端只能登记普通敏感度证据")
        cur = conn.execute(
            "INSERT INTO evidences (clue_id, label, content_ref, sensitivity, kind, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)",
            (clue_id, label, content_ref, sensitivity, kind, actor["id"]),
        )
        return cur.lastrowid

    def add_evidence(self, user: sqlite3.Row, clue_ref: str, payload: dict) -> dict:
        self.require("clue.register_receipt", user)
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            if row["merged_into"] is not None:
                raise ConflictError("请向合并后的主线索补充证据")
            if row["state"] not in OPEN_STATES:
                raise ConflictError(f"「{row['state']}」状态不能补充证据")
            ev_id = self._insert_evidence(conn, user, row["id"], payload)
            self._audit(
                conn, actor=user, action="evidence.add", clue_id=row["id"],
                reason=f"补充证据：{payload.get('label')}",
                detail={"evidence_id": ev_id, "sensitivity": payload.get("sensitivity", "普通"), "kind": payload.get("kind", "文档")},
            )
            # 证据变化后刷新建议分（已确认优先级不受影响）。
            self._score_clue(conn, row)
            return {"evidence_id": ev_id, "clue_id": row["id"]}

    # ---- 临时措施 ----------------------------------------------------------

    def create_measure(self, user: sqlite3.Row, clue_ref: str, measure_type: str, detail: str) -> dict:
        self.require("measure.create", user)
        if not measure_type:
            raise ValidationError("措施类型不能为空")
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            if row["state"] not in (STATE_PENDING_VERIFY, STATE_PROCESSING):
                raise ConflictError(f"「{row['state']}」状态不能采取临时措施")
            cur = conn.execute(
                "INSERT INTO interim_measures (clue_id, measure_type, detail, created_by) VALUES (?, ?, ?, ?)",
                (row["id"], measure_type, detail, user["id"]),
            )
            self._audit(conn, actor=user, action="measure.create", clue_id=row["id"],
                        reason=f"采取临时措施：{measure_type}", detail={"measure_id": cur.lastrowid, "detail": detail})
            return {"measure_id": cur.lastrowid, "status": "生效中"}

    def lift_measure(self, user: sqlite3.Row, measure_id: int, reason: str) -> dict:
        self.require("measure.lift", user)
        if not reason:
            raise ValidationError("解除措施必须填写理由")
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM interim_measures WHERE id = ?", (measure_id,)).fetchone()
            if row is None:
                raise NotFoundError("临时措施不存在")
            if row["status"] != "生效中":
                raise ConflictError("措施已解除，不能重复操作")
            conn.execute(
                "UPDATE interim_measures SET status = '已解除', lifted_by = ?, lifted_at = ? WHERE id = ?",
                (user["id"], now_str(), measure_id),
            )
            self._audit(conn, actor=user, action="measure.lift", clue_id=row["clue_id"],
                        reason=reason, detail={"measure_id": measure_id, "measure_type": row["measure_type"]})
            return {"measure_id": measure_id, "status": "已解除"}

    # ---- 延期 --------------------------------------------------------------

    def request_extension(self, user: sqlite3.Row, clue_ref: str, hours: int, reason: str) -> dict:
        self.require("extension.request", user)
        if hours <= 0:
            raise ValidationError("延期小时数必须为正整数")
        if not reason:
            raise ValidationError("延期必须说明理由")
        with self._tx() as conn:
            row = self._get_clue(conn, clue_ref)
            if row["due_at"] is None:
                raise ConflictError("该线索尚未确认办理时限")
            if row["state"] not in (STATE_PENDING_VERIFY, STATE_PROCESSING):
                raise ConflictError(f"「{row['state']}」状态不能申请延期")
            pending = conn.execute(
                "SELECT 1 FROM extensions WHERE clue_id = ? AND status = '待审批'", (row["id"],)
            ).fetchone()
            if pending:
                raise ConflictError("已有待审批的延期申请")
            cur = conn.execute(
                "INSERT INTO extensions (clue_id, hours, reason, requested_by) VALUES (?, ?, ?, ?)",
                (row["id"], hours, reason, user["id"]),
            )
            self._audit(conn, actor=user, action="extension.request", clue_id=row["id"],
                        reason=f"申请延期 {hours} 小时：{reason}", detail={"extension_id": cur.lastrowid, "hours": hours})
            return {"extension_id": cur.lastrowid, "status": "待审批"}

    def decide_extension(self, user: sqlite3.Row, extension_id: int, approve: bool, comment: str = "") -> dict:
        self.require("extension.approve", user)
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM extensions WHERE id = ?", (extension_id,)).fetchone()
            if row is None:
                raise NotFoundError("延期申请不存在")
            if row["status"] != "待审批":
                raise ConflictError("该申请已处理")
            clue = self._get_clue(conn, row["clue_id"])
            new_status = "已批准" if approve else "已驳回"
            conn.execute(
                "UPDATE extensions SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?",
                (new_status, user["id"], now_str(), extension_id),
            )
            detail = {"extension_id": extension_id, "hours": row["hours"], "comment": comment}
            new_due = clue["due_at"]
            if approve:
                base = parse(clue["due_at"]) or now()
                new_due = ts_str(base + timedelta(hours=row["hours"]))
                records = json.loads(clue["deadline_extensions"])
                records.append({"extension_id": extension_id, "hours": row["hours"], "new_due_at": new_due,
                                "reason": row["reason"], "decided_by": user["display_name"]})
                conn.execute(
                    "UPDATE clues SET due_at = ?, deadline_extensions = ?, updated_at = ? WHERE id = ?",
                    (new_due, json.dumps(records, ensure_ascii=False), now_str(), clue["id"]),
                )
            self._audit(
                conn, actor=user, action="extension.approve" if approve else "extension.reject",
                clue_id=clue["id"], reason=comment or row["reason"], detail=detail,
            )
            return {"extension_id": extension_id, "status": new_status, "due_at": new_due}

    def list_extensions(self, user: sqlite3.Row, status: str | None = None) -> list[dict]:
        self.require("extension.approve", user)
        sql = """SELECT e.*, c.clue_no, c.title, u.display_name AS requested_by_name,
                        d.display_name AS decided_by_name
                 FROM extensions e JOIN clues c ON c.id = e.clue_id
                 LEFT JOIN users u ON u.id = e.requested_by
                 LEFT JOIN users d ON d.id = e.decided_by"""
        args: list = []
        if status:
            sql += " WHERE e.status = ?"
            args.append(status)
        sql += " ORDER BY e.id DESC"
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    # ---- 审计 --------------------------------------------------------------

    def list_audit(self, user: sqlite3.Row, clue_ref: str | None = None, limit: int = 100) -> list[dict]:
        self.require("clue.audit", user)
        sql = """SELECT a.* FROM audit_logs a"""
        args: list = []
        if clue_ref:
            clue = self._get_clue(self.conn, clue_ref)
            sql += " WHERE a.clue_id = ?"
            args.append(clue["id"])
        sql += " ORDER BY a.id DESC LIMIT ?"
        args.append(min(limit, 500))
        rows = self.conn.execute(sql, args).fetchall()
        result = []
        for r in rows:
            item = {
                "id": r["id"],
                "clue_id": r["clue_id"],
                "actor": r["actor_name"],
                "actor_role": r["actor_role"],
                "action": r["action"],
                "from_state": r["from_state"],
                "to_state": r["to_state"],
                "reason": r["reason"],
                "detail": json.loads(r["detail_json"]),
                "created_at": r["created_at"],
            }
            result.append(item)
        return result

    # ---- 详情（按角色裁剪证据） --------------------------------------------

    @staticmethod
    def _mask(value: str, keep_head: int = 1, keep_tail: int = 1) -> str:
        if not value:
            return ""
        if len(value) <= keep_head + keep_tail:
            return "*" * len(value)
        return value[:keep_head] + "*" * (len(value) - keep_head - keep_tail) + value[-keep_tail:]

    def _can_see(self, user: sqlite3.Row, level: str) -> bool:
        ceiling = ROLE_MAX_SENSITIVITY[user["role"]]
        return SENS_RANK[level] <= SENS_RANK[ceiling]

    def _evidence_view(self, user: sqlite3.Row, rows: list[sqlite3.Row]) -> list[dict]:
        result: list[dict] = []
        for ev in rows:
            if self._can_see(user, ev["sensitivity"]):
                result.append(
                    {
                        "evidence_id": ev["id"],
                        "label": ev["label"],
                        "kind": ev["kind"],
                        "sensitivity": ev["sensitivity"],
                        "content_ref": ev["content_ref"],
                        "created_at": ev["created_at"],
                        "redacted": False,
                    }
                )
            else:
                # 超出角色可见等级：只保留存在性与分级，不暴露名称与内容指针。
                result.append(
                    {
                        "evidence_id": ev["id"],
                        "kind": ev["kind"],
                        "sensitivity": ev["sensitivity"],
                        "redacted": True,
                        "redact_reason": "证据敏感度超出当前角色可见范围",
                    }
                )
        return result

    def get_clue_detail(self, user: sqlite3.Row, clue_ref: str) -> dict:
        self.require("clue.read", user)
        conn = self.conn
        row = self._get_clue(conn, clue_ref)
        subject = conn.execute("SELECT * FROM subjects WHERE id = ?", (row["subject_id"],)).fetchone()
        lease = self._active_lease(conn, row["id"])

        high_clearance = self._can_see(user, "敏感")
        subject_identifier = subject["identifier"]
        if not high_clearance and subject["subject_type"] == "人员":
            subject_identifier = self._mask(subject_identifier, 1, 1)
        reporter_contact = row["reporter_contact"]
        if not high_clearance:
            reporter_contact = self._mask(reporter_contact, 1, 1)

        evidences = conn.execute(
            "SELECT * FROM evidences WHERE clue_id = ? ORDER BY id", (row["id"],)
        ).fetchall()
        measures = [
            dict(m)
            for m in conn.execute(
                "SELECT * FROM interim_measures WHERE clue_id = ? ORDER BY id", (row["id"],)
            ).fetchall()
        ]
        extensions = [
            dict(e)
            for e in conn.execute(
                """SELECT e.id, e.hours, e.reason, e.status, e.created_at, e.decided_at,
                          u.display_name AS requested_by_name, d.display_name AS decided_by_name
                   FROM extensions e
                   LEFT JOIN users u ON u.id = e.requested_by
                   LEFT JOIN users d ON d.id = e.decided_by
                   WHERE e.clue_id = ? ORDER BY e.id""",
                (row["id"],),
            ).fetchall()
        ]
        merges = [
            dict(m)
            for m in conn.execute(
                """SELECT m.id, m.primary_clue_id, m.duplicate_clue_id, m.score, m.reason, m.status,
                          p.clue_no AS primary_clue_no, d.clue_no AS duplicate_clue_no
                   FROM merge_suggestions m
                   JOIN clues p ON p.id = m.primary_clue_id
                   JOIN clues d ON d.id = m.duplicate_clue_id
                   WHERE m.primary_clue_id = ? OR m.duplicate_clue_id = ?
                   ORDER BY m.id DESC""",
                (row["id"], row["id"]),
            ).fetchall()
        ]
        children = [
            {"clue_id": c["id"], "clue_no": c["clue_no"], "title": c["title"], "state": c["state"]}
            for c in conn.execute(
                "SELECT id, clue_no, title, state FROM clues WHERE parent_id = ? ORDER BY id", (row["id"],)
            ).fetchall()
        ]
        parent = None
        if row["parent_id"]:
            p = conn.execute("SELECT id, clue_no, title FROM clues WHERE id = ?", (row["parent_id"],)).fetchone()
            parent = {"clue_id": p["id"], "clue_no": p["clue_no"], "title": p["title"]}
        primary = None
        if row["merged_into"]:
            p = conn.execute("SELECT id, clue_no, title FROM clues WHERE id = ?", (row["merged_into"],)).fetchone()
            primary = {"clue_id": p["id"], "clue_no": p["clue_no"], "title": p["title"]}

        due = parse(row["due_at"])
        audits = self.list_audit(user, row["id"], limit=200)
        return {
            "clue_id": row["id"],
            "clue_no": row["clue_no"],
            "title": row["title"],
            "description": row["description"],
            "source_channel": row["source_channel"],
            "source_ref": row["source_ref"],
            "fingerprint": row["fingerprint"],
            "occurrence_at": row["occurrence_at"],
            "region": row["region"],
            "subject": {
                "subject_type": subject["subject_type"],
                "name": subject["name"],
                "identifier": subject_identifier,
            },
            "reporter_contact": reporter_contact,
            "state": row["state"],
            "priority": row["priority"],
            "suggested_priority": row["suggested_priority"],
            "priority_reason": row["priority_reason"],
            "risk": {
                "risk_score": row["risk_score"],
                "risk_hits": json.loads(row["risk_hits"]),
                "rule_version": row["rule_version"],
            },
            "due_at": row["due_at"],
            "overdue": bool(due and due < now() and row["state"] in OPEN_STATES),
            "deadline_extensions": json.loads(row["deadline_extensions"]),
            "lease": (
                {
                    "holder": lease["holder_name"],
                    "expires_at": lease["expires_at"],
                    "mine": lease["holder_id"] == user["id"],
                }
                if lease
                else None
            ),
            "evidences": self._evidence_view(user, evidences),
            "evidence_visibility": {
                "role": user["role"],
                "max_sensitivity": ROLE_MAX_SENSITIVITY[user["role"]],
                "total": len(evidences),
                "visible": sum(1 for e in evidences if self._can_see(user, e["sensitivity"])),
            },
            "interim_measures": measures,
            "extensions": extensions,
            "merge_suggestions": merges,
            "merged_into": primary,
            "parent": parent,
            "children": children,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "audit_trail": audits,
        }
