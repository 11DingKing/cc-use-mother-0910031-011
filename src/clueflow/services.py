"""应用服务层：全部用例与领域约束。

约定：
- 每个公开变更方法开启一个 store.tx() 事务；私有辅助方法不得自行开事务；
- 所有变更写入审计事件（含操作理由），保证“每次分流可追溯”；
- 处置类操作（核验、决定、措施、延期申请等）要求有效租约令牌；
- 合并与优先级由系统给出建议，须监管人员/复核专家确认后生效。
"""
from __future__ import annotations

import uuid

from . import fingerprint, redaction, risk, timeutil
from .constants import (
    ACTIVE_STATES,
    CHANNELS,
    DECISIONS,
    EVIDENCE_KINDS,
    LEASE_TTL_DEFAULT_SECONDS,
    LEASE_TTL_MAX_SECONDS,
    MAX_EXTENSION_DAYS,
    MAX_EXTENSIONS_PER_CYCLE,
    MEASURE_TYPES,
    MERGE_SCORE_THRESHOLD,
    PRIORITIES,
    PRIORITY_RANK,
    PRIORITY_SLA_DAYS,
    ROLES,
    STATES,
    SUBJECT_TYPES,
    TRANSITIONS,
)
from .errors import (
    DomainViolation,
    Forbidden,
    LeaseConflict,
    LeaseRequired,
    NotFound,
    StateConflict,
    Unauthorized,
    ValidationError,
)
from .models import Actor
from .seed import seed_base
from .store import Store, dumps, loads

_CONFIRM_ROLES = ("监管人员", "复核专家")


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise ValidationError(message)


def _require_reason(reason: str | None) -> str:
    reason = (reason or "").strip()
    if not reason:
        raise ValidationError("必须填写操作理由（reason）")
    return reason


class ClueflowService:
    def __init__(self, store: Store):
        self.store = store
        seed_base(store)

    # ================================================================
    # 基础：账号 / 元信息
    # ================================================================
    def authenticate(self, actor_id: str | None) -> Actor:
        if not actor_id:
            raise Unauthorized("缺少 X-Actor-Id 请求头")
        row = self.store.one("SELECT * FROM actors WHERE id=?", (actor_id,))
        if row is None:
            raise Unauthorized(f"未知账号：{actor_id}")
        return Actor(id=row["id"], name=row["name"], role=row["role"], org_id=row["org_id"])

    def list_actors(self) -> list[dict]:
        return self.store.all("SELECT id, name, role, org_id FROM actors ORDER BY id")

    def meta(self) -> dict:
        return {
            "product": "违规线索分流处置",
            "roles": list(ROLES),
            "states": list(STATES),
            "channels": list(CHANNELS),
            "priorities": list(PRIORITIES),
            "priority_sla_days": PRIORITY_SLA_DAYS,
            "decisions": list(DECISIONS),
            "measure_types": list(MEASURE_TYPES),
            "evidence_kinds": list(EVIDENCE_KINDS),
            "transitions": {
                action: {
                    "from": sorted(spec["from"]),
                    "to": spec["to"],
                    "roles": sorted(spec["roles"]),
                    "lease_required": spec["lease"],
                }
                for action, spec in TRANSITIONS.items()
            },
            "risk_rule_version": int(self.store.get_meta("risk_rule_version") or 0),
        }

    # ================================================================
    # 内部：通用读取与校验
    # ================================================================
    def _get_case_row(self, case_id: str) -> dict:
        row = self.store.one("SELECT * FROM cases WHERE id=?", (case_id,))
        if row is None:
            raise NotFound(f"案件不存在：{case_id}")
        return row

    def _get_clue_row(self, clue_id: str) -> dict:
        row = self.store.one("SELECT * FROM clues WHERE id=?", (clue_id,))
        if row is None:
            raise NotFound(f"线索不存在：{clue_id}")
        return row

    def _visible(self, actor: Actor, case_id: str) -> bool:
        """数据可见性：监管/专家全量；机构合规员限本机构涉案或本账号登记；执业人员限涉案本人。"""
        if actor.role in _CONFIRM_ROLES:
            return True
        if actor.role == "机构合规员":
            row = self.store.one(
                "SELECT 1 AS x FROM case_subjects cs JOIN subjects s ON s.id=cs.subject_id "
                "WHERE cs.case_id=? AND s.org_id=? LIMIT 1",
                (case_id, actor.org_id or ""),
            )
            if row:
                return True
            row = self.store.one(
                "SELECT 1 AS x FROM case_clues cc JOIN clues c ON c.id=cc.clue_id "
                "WHERE cc.case_id=? AND c.created_by=? LIMIT 1",
                (case_id, actor.id),
            )
            return row is not None
        if actor.role == "执业人员":
            row = self.store.one(
                "SELECT 1 AS x FROM case_subjects cs JOIN subjects s ON s.id=cs.subject_id "
                "WHERE cs.case_id=? AND s.identifier=? LIMIT 1",
                (case_id, actor.id),
            )
            return row is not None
        return False

    def _require_visible(self, actor: Actor, case_id: str) -> None:
        if not self._visible(actor, case_id):
            raise Forbidden("无权查看该案件")

    @staticmethod
    def _require_role(actor: Actor, *roles: str) -> None:
        if actor.role not in roles:
            raise Forbidden(f"角色[{actor.role}]无权执行该操作")

    def _active_lease(self, case: dict) -> dict | None:
        if not case["lease_holder"] or not case["lease_expires_at"]:
            return None
        if timeutil.parse(case["lease_expires_at"]) <= timeutil.utcnow():
            return None
        return {
            "holder_id": case["lease_holder"],
            "fencing": case["lease_fencing"],
            "expires_at": case["lease_expires_at"],
        }

    def _require_lease(self, case: dict, actor: Actor, token: str | None) -> None:
        """处置操作必须持有有效租约：持有人匹配 + 令牌（含 fencing）匹配 + 未过期。"""
        if not token:
            raise LeaseRequired("该操作需要有效租约令牌（lease_token）")
        if case["lease_holder"] != actor.id or case["lease_token"] != token:
            raise LeaseConflict("租约不属于当前操作者或令牌已失效")
        if timeutil.parse(case["lease_expires_at"]) <= timeutil.utcnow():
            raise LeaseConflict("租约已过期，请重新认领")

    def _audit(
        self,
        case_id: str,
        actor: Actor,
        action: str,
        reason: str | None = None,
        detail: dict | None = None,
        from_state: str | None = None,
        to_state: str | None = None,
    ) -> None:
        self.store.execute(
            "INSERT INTO audits(case_id, actor_id, actor_role, action, reason, detail, "
            "from_state, to_state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                case_id,
                actor.id,
                actor.role,
                action,
                reason,
                dumps(detail) if detail else None,
                from_state,
                to_state,
                timeutil.now_iso(),
            ),
        )

    def _touch(self, case_id: str) -> None:
        self.store.execute(
            "UPDATE cases SET updated_at=? WHERE id=?", (timeutil.now_iso(), case_id)
        )

    @staticmethod
    def _due_at(cycle_started_at: str, priority: str, extension_days: int) -> str:
        return timeutil.add_days(cycle_started_at, PRIORITY_SLA_DAYS[priority] + extension_days)

    # ================================================================
    # 主体（涉及主体）
    # ================================================================
    def _find_or_create_subject(self, data: dict) -> str:
        identifier = (data.get("identifier") or "").strip()
        name = (data.get("name") or "").strip()
        stype = data.get("type")
        _require(stype in SUBJECT_TYPES, f"主体类型须为：{'、'.join(SUBJECT_TYPES)}")
        _require(bool(name), "主体名称不能为空")
        _require(bool(identifier), "主体标识（统一社会信用代码/执业证号）不能为空")
        row = self.store.one("SELECT id FROM subjects WHERE identifier=?", (identifier,))
        if row:
            return row["id"]
        subject_id = self.store.next_id("SUB")
        self.store.execute(
            "INSERT INTO subjects(id, type, name, identifier, org_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                subject_id,
                stype,
                name,
                identifier,
                data.get("org_id"),
                timeutil.now_iso(),
            ),
        )
        return subject_id

    def create_subject(self, actor: Actor, data: dict) -> dict:
        self._require_role(actor, *_CONFIRM_ROLES)
        with self.store.tx():
            subject_id = self._find_or_create_subject(data)
        row = self.store.one("SELECT * FROM subjects WHERE id=?", (subject_id,))
        return redaction.subject_view(actor.role, row)

    def list_subjects(self, actor: Actor) -> list[dict]:
        rows = self.store.all("SELECT * FROM subjects ORDER BY id")
        return [redaction.subject_view(actor.role, r) for r in rows]

    # ================================================================
    # 线索登记 + 自动去重建议 + 自动初评
    # ================================================================
    def register_clue(self, actor: Actor, data: dict) -> dict:
        self._require_role(actor, "机构合规员", "监管人员")
        channel = data.get("channel")
        _require(channel in CHANNELS, f"来源渠道须为：{'、'.join(CHANNELS)}")
        if actor.role == "机构合规员" and channel != "机构自报":
            raise Forbidden("机构合规员仅可登记机构自报线索")
        title = (data.get("title") or "").strip()
        content = (data.get("content") or "").strip()
        _require(bool(title), "标题不能为空")
        _require(bool(content), "内容不能为空")
        subjects_data = data.get("subjects") or []
        _require(isinstance(subjects_data, list) and len(subjects_data) >= 1, "至少登记一个涉及主体")
        reporter = data.get("reporter") or {}
        anonymous = bool(data.get("anonymous"))

        with self.store.tx():
            subject_ids = [self._find_or_create_subject(s) for s in subjects_data]
            identifiers = [
                self.store.one("SELECT identifier FROM subjects WHERE id=?", (sid,))["identifier"]
                for sid in subject_ids
            ]
            clue_id = self.store.next_id("CLU")
            case_id = self.store.next_id("CAS")
            now = timeutil.now_iso()
            fp = fingerprint.source_fingerprint(
                channel, identifiers, content, data.get("event_date")
            )
            tokens = sorted(fingerprint.content_tokens(title + " " + content))
            self.store.execute(
                "INSERT INTO clues(id, channel, title, content, event_date, location, "
                "reporter_name, reporter_contact_hash, anonymous, fingerprint, tokens, status, "
                "case_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    clue_id,
                    channel,
                    title,
                    content,
                    data.get("event_date"),
                    data.get("location"),
                    (reporter.get("name") or "").strip() or None,
                    fingerprint.contact_hash(reporter.get("contact")),
                    1 if anonymous else 0,
                    fp,
                    dumps(tokens),
                    "登记",
                    case_id,
                    actor.id,
                    now,
                ),
            )
            # 每条线索先独立成案（登记态），等待去重建议确认后可能并入他案
            self.store.execute(
                "INSERT INTO cases(id, title, state, priority, priority_status, rule_version, "
                "assignee_id, org_id, decision, registered_at, cycle_started_at, due_at, "
                "created_at, updated_at) VALUES (?, ?, '登记', '中', '待确认', 0, NULL, ?, NULL, ?, ?, ?, ?, ?)",
                (case_id, title, data.get("org_id"), now, now, self._due_at(now, "中", 0), now, now),
            )
            self.store.execute(
                "INSERT INTO case_clues(case_id, clue_id, linked_at) VALUES (?, ?, ?)",
                (case_id, clue_id, now),
            )
            for sid in subject_ids:
                self.store.execute(
                    "INSERT OR IGNORE INTO case_subjects(case_id, subject_id) VALUES (?, ?)",
                    (case_id, sid),
                )
            # 随线索一并提交的证据
            for ev in data.get("evidence") or []:
                self._insert_evidence(actor, case_id, ev)
            self._audit(
                case_id, actor, "登记线索",
                reason=f"渠道：{channel}",
                detail={"clue_id": clue_id, "fingerprint": fp},
                to_state="登记",
            )
            assessment = self._assess_priority(case_id)
            suggestions = self._scan_duplicates(case_id, clue_id, fp, set(tokens), set(identifiers))
            self._touch(case_id)

        return {
            "clue": self.get_clue(actor, clue_id),
            "case": self.get_case(actor, case_id),
            "priority_assessment": assessment,
            "merge_suggestions": suggestions,
        }

    def _scan_duplicates(
        self,
        source_case_id: str,
        clue_id: str,
        fp: str,
        tokens: set[str],
        identifiers: set[str],
    ) -> list[dict]:
        """对在办案件扫描重复线索，生成待确认合并建议（含命中理由）。"""
        candidates = self.store.all(
            "SELECT c.* FROM clues c JOIN cases k ON k.id=c.case_id "
            "WHERE c.case_id != ? AND k.state IN ('登记', '待核验', '处置中')",
            (source_case_id,),
        )
        created: list[dict] = []
        for cand in candidates:
            cand_tokens = set(loads(cand["tokens"]))
            sim = fingerprint.jaccard(tokens, cand_tokens)
            cand_subjects = {
                r["identifier"]
                for r in self.store.all(
                    "SELECT s.identifier FROM case_subjects cs JOIN subjects s ON s.id=cs.subject_id "
                    "WHERE cs.case_id=?",
                    (cand["case_id"],),
                )
            }
            shared = identifiers & cand_subjects
            fp_match = cand["fingerprint"] == fp
            score = fingerprint.merge_score(
                fp_match, sim, len(shared), len(identifiers | cand_subjects)
            )
            if not fp_match and score < MERGE_SCORE_THRESHOLD:
                continue
            if not fp_match and not shared and sim < 0.6:
                continue  # 既无共同主体又非精确指纹时，要求更高内容相似度
            suggestion_id = self.store.next_id("MRG")
            signals = {
                "fingerprint_match": fp_match,
                "content_similarity": round(sim, 4),
                "shared_subjects": sorted(shared),
                "matched_clue_id": cand["id"],
                "matched_case_id": cand["case_id"],
                "matched_case_title": cand["title"],
            }
            self.store.execute(
                "INSERT INTO merge_suggestions(id, clue_id, source_case_id, target_case_id, "
                "score, signals, status, created_at) VALUES (?, ?, ?, ?, ?, ?, '待确认', ?)",
                (
                    suggestion_id,
                    clue_id,
                    source_case_id,
                    cand["case_id"],
                    score,
                    dumps(signals),
                    timeutil.now_iso(),
                ),
            )
            self._audit(
                source_case_id,
                Actor(id="system", name="系统", role="系统"),
                "生成合并建议",
                reason=(
                    f"与案件 {cand['case_id']} 疑似重复（得分 {score}）："
                    + ("来源指纹一致" if fp_match else f"内容相似度 {sim:.2f}，共同主体 {len(shared)} 个")
                ),
                detail={"suggestion_id": suggestion_id, **signals},
            )
            created.append({"id": suggestion_id, "score": score, "status": "待确认", **signals})
        return created

    def get_clue(self, actor: Actor, clue_id: str) -> dict:
        clue = self._get_clue_row(clue_id)
        if clue["case_id"]:
            self._require_visible(actor, clue["case_id"])
        return self._clue_view(actor, clue)

    def list_clues(self, actor: Actor, query: dict) -> list[dict]:
        rows = self.store.all("SELECT * FROM clues ORDER BY created_at DESC, id DESC")
        result = []
        for row in rows:
            if query.get("channel") and row["channel"] != query["channel"]:
                continue
            if row["case_id"] and not self._visible(actor, row["case_id"]):
                continue
            result.append(self._clue_view(actor, row))
        return result

    def _clue_view(self, actor: Actor, clue: dict) -> dict:
        return {
            "id": clue["id"],
            "channel": clue["channel"],
            "title": clue["title"],
            "content": clue["content"],
            "event_date": clue["event_date"],
            "location": clue["location"],
            "reporter": redaction.reporter_view(actor.role, clue),
            "fingerprint": clue["fingerprint"],
            "status": clue["status"],
            "case_id": clue["case_id"],
            "created_by": clue["created_by"],
            "created_at": clue["created_at"],
        }

    # ================================================================
    # 风险初评（版本化）
    # ================================================================
    def _current_rules(self) -> tuple[int, list[dict]]:
        version = int(self.store.get_meta("risk_rule_version") or 0)
        rows = self.store.all(
            "SELECT * FROM risk_rules WHERE version=? AND enabled=1 ORDER BY id", (version,)
        )
        rules = [{**r, "params": loads(r["params"])} for r in rows]
        return version, rules

    def _build_context(self, case_id: str) -> risk.AssessmentContext:
        clues = self.store.all(
            "SELECT c.* FROM clues c JOIN case_clues cc ON cc.clue_id=c.id WHERE cc.case_id=?",
            (case_id,),
        )
        subjects = self.store.all(
            "SELECT s.* FROM case_subjects cs JOIN subjects s ON s.id=cs.subject_id WHERE cs.case_id=?",
            (case_id,),
        )
        recidivists = []
        for subj in subjects:
            row = self.store.one(
                "SELECT 1 AS x FROM case_subjects cs JOIN cases k ON k.id=cs.case_id "
                "WHERE cs.subject_id=? AND k.id!=? AND k.decision='立案查处' "
                "AND k.state IN ('已决定', '已归档') LIMIT 1",
                (subj["id"], case_id),
            )
            if row:
                recidivists.append(subj["name"])
        sens = self.store.one(
            "SELECT COALESCE(MAX(sensitivity), 0) AS m FROM evidence WHERE case_id=?", (case_id,)
        )
        return risk.AssessmentContext(
            channels={c["channel"] for c in clues},
            contents=[c["title"] + " " + c["content"] for c in clues],
            clue_count=len(clues),
            max_sensitivity=int(sens["m"]),
            recidivist_subjects=recidivists,
        )

    def _assess_priority(self, case_id: str) -> dict:
        """生成待确认的优先级建议；案件暂按建议级别排序，确认后转正。"""
        version, rules = self._current_rules()
        ctx = self._build_context(case_id)
        score, hits = risk.evaluate(rules, ctx)
        level = risk.level_for_score(score)
        assessment_id = self.store.next_id("PRI")
        now = timeutil.now_iso()
        self.store.execute(
            "INSERT INTO priority_assessments(id, case_id, rule_version, score, suggested_level, "
            "hits, status, created_at) VALUES (?, ?, ?, ?, ?, ?, '待确认', ?)",
            (assessment_id, case_id, version, score, level, dumps([h.as_dict() for h in hits]), now),
        )
        case = self._get_case_row(case_id)
        self.store.execute(
            "UPDATE cases SET priority=?, priority_status='待确认', rule_version=?, due_at=? WHERE id=?",
            (level, version, self._due_at(case["cycle_started_at"], level, case["extension_days"]), case_id),
        )
        self._audit(
            case_id,
            Actor(id="system", name="系统", role="系统"),
            "风险初评",
            reason=(
                f"规则版本 v{version}，得分 {score}，建议级别[{level}]；命中："
                + ("、".join(h.name for h in hits) if hits else "无")
            ),
            detail={"assessment_id": assessment_id, "score": score, "hits": [h.as_dict() for h in hits]},
        )
        return {
            "id": assessment_id,
            "case_id": case_id,
            "rule_version": version,
            "score": score,
            "suggested_level": level,
            "hits": [h.as_dict() for h in hits],
            "status": "待确认",
            "created_at": now,
        }

    def confirm_priority(self, actor: Actor, case_id: str, data: dict) -> dict:
        """授权人员确认或调整优先级建议。"""
        self._require_role(actor, *_CONFIRM_ROLES)
        reason = _require_reason(data.get("reason"))
        case = self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        accept = bool(data.get("accept", True))
        adjust_level = data.get("level")
        if not accept:
            _require(adjust_level in PRIORITIES, f"调整级别须为：{'、'.join(PRIORITIES)}")
        with self.store.tx():
            assessment = self.store.one(
                "SELECT * FROM priority_assessments WHERE case_id=? ORDER BY created_at DESC, id DESC LIMIT 1",
                (case_id,),
            )
            _require(assessment is not None, "该案件尚无优先级评估")
            if assessment["status"] != "待确认":
                raise StateConflict("最新评估已确认，如需变更请触发重评")
            final_level = assessment["suggested_level"] if accept else adjust_level
            status = "已确认" if accept else "已调整"
            now = timeutil.now_iso()
            self.store.execute(
                "UPDATE priority_assessments SET status=?, confirmed_by=?, confirmed_level=?, "
                "decided_at=?, reason=? WHERE id=?",
                (status, actor.id, final_level, now, reason, assessment["id"]),
            )
            self.store.execute(
                "UPDATE cases SET priority=?, priority_status='已确认', due_at=? WHERE id=?",
                (final_level, self._due_at(case["cycle_started_at"], final_level, case["extension_days"]), case_id),
            )
            self._audit(
                case_id, actor, "确认优先级",
                reason=reason,
                detail={
                    "assessment_id": assessment["id"],
                    "suggested_level": assessment["suggested_level"],
                    "final_level": final_level,
                    "adjusted": not accept,
                },
            )
            self._touch(case_id)
        return self.get_case(actor, case_id)

    # ================================================================
    # 案件查询（按角色裁剪）
    # ================================================================
    def get_case(self, actor: Actor, case_id: str) -> dict:
        case = self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        return self._case_view(actor, case)

    def list_cases(self, actor: Actor, query: dict) -> dict:
        rows = self.store.all("SELECT * FROM cases")
        now = timeutil.utcnow()
        items = []
        for case in rows:
            if not self._visible(actor, case["id"]):
                continue
            if query.get("state") and case["state"] != query["state"]:
                continue
            if query.get("priority") and case["priority"] != query["priority"]:
                continue
            if query.get("assignee_id") and case["assignee_id"] != query["assignee_id"]:
                continue
            overdue = case["state"] in ACTIVE_STATES and timeutil.parse(case["due_at"]) < now
            if query.get("overdue") in ("1", "true") and not overdue:
                continue
            if query.get("q") and query["q"] not in case["title"]:
                continue
            items.append((case, overdue))
        items.sort(key=lambda t: (-PRIORITY_RANK[t[0]["priority"]], t[0]["due_at"], t[0]["id"]))
        try:
            offset = max(0, int(query.get("offset", 0)))
            limit = min(200, max(1, int(query.get("limit", 50))))
        except ValueError:
            raise ValidationError("limit/offset 须为整数")
        page = items[offset : offset + limit]
        return {
            "total": len(items),
            "offset": offset,
            "limit": limit,
            "items": [
                {
                    "id": c["id"],
                    "title": c["title"],
                    "state": c["state"],
                    "priority": c["priority"],
                    "priority_status": c["priority_status"],
                    "assignee_id": c["assignee_id"],
                    "due_at": c["due_at"],
                    "overdue": od,
                    "lease_holder": (self._active_lease(c) or {}).get("holder_id"),
                    "updated_at": c["updated_at"],
                }
                for c, od in page
            ],
        }

    def _case_view(self, actor: Actor, case: dict) -> dict:
        case_id = case["id"]
        subjects = self.store.all(
            "SELECT s.* FROM case_subjects cs JOIN subjects s ON s.id=cs.subject_id WHERE cs.case_id=? ORDER BY s.id",
            (case_id,),
        )
        clues = self.store.all(
            "SELECT c.* FROM clues c JOIN case_clues cc ON cc.clue_id=c.id WHERE cc.case_id=? ORDER BY c.created_at",
            (case_id,),
        )
        evidence = self.store.all(
            "SELECT * FROM evidence WHERE case_id=? ORDER BY created_at", (case_id,)
        )
        ev_views, ev_hidden = redaction.redact_evidence_list(actor.role, evidence)
        measures = self.store.all(
            "SELECT * FROM measures WHERE case_id=? ORDER BY imposed_at", (case_id,)
        )
        extensions = self.store.all(
            "SELECT * FROM extensions WHERE case_id=? ORDER BY created_at", (case_id,)
        )
        pending_merges = self.store.all(
            "SELECT * FROM merge_suggestions WHERE status='待确认' AND (source_case_id=? OR target_case_id=?)",
            (case_id, case_id),
        )
        assessment = self.store.one(
            "SELECT * FROM priority_assessments WHERE case_id=? ORDER BY created_at DESC, id DESC LIMIT 1",
            (case_id,),
        )
        audits = self.store.all(
            "SELECT * FROM audits WHERE case_id=? ORDER BY id DESC LIMIT 5", (case_id,)
        )
        children = self.store.all("SELECT id FROM cases WHERE parent_id=? ORDER BY id", (case_id,))
        lease = self._active_lease(case)
        overdue = case["state"] in ACTIVE_STATES and timeutil.parse(case["due_at"]) < timeutil.utcnow()
        return {
            "id": case_id,
            "title": case["title"],
            "state": case["state"],
            "priority": case["priority"],
            "priority_status": case["priority_status"],
            "rule_version": case["rule_version"],
            "assignee_id": case["assignee_id"],
            "org_id": case["org_id"],
            "decision": case["decision"],
            "registered_at": case["registered_at"],
            "cycle_started_at": case["cycle_started_at"],
            "due_at": case["due_at"],
            "overdue": overdue,
            "decided_at": case["decided_at"],
            "archived_at": case["archived_at"],
            "reopened_count": case["reopened_count"],
            "extension_count": case["extension_count"],
            "extension_days": case["extension_days"],
            "parent_id": case["parent_id"],
            "children": [c["id"] for c in children],
            "lease": lease,
            "subjects": [redaction.subject_view(actor.role, s) for s in subjects],
            "clues": [self._clue_view(actor, c) for c in clues],
            "evidence": ev_views,
            "evidence_hidden": ev_hidden,
            "measures": measures,
            "extensions": extensions,
            "pending_merge_suggestions": [
                {
                    "id": m["id"],
                    "direction": "并入他案" if m["source_case_id"] == case_id else "接收他案",
                    "other_case_id": m["target_case_id"] if m["source_case_id"] == case_id else m["source_case_id"],
                    "score": m["score"],
                    "signals": loads(m["signals"]),
                }
                for m in pending_merges
            ],
            "latest_assessment": (
                {
                    "id": assessment["id"],
                    "rule_version": assessment["rule_version"],
                    "score": assessment["score"],
                    "suggested_level": assessment["suggested_level"],
                    "hits": loads(assessment["hits"]),
                    "status": assessment["status"],
                    "confirmed_level": assessment["confirmed_level"],
                }
                if assessment
                else None
            ),
            "recent_audit": [self._audit_view(a) for a in audits],
        }

    @staticmethod
    def _audit_view(row: dict) -> dict:
        return {
            "id": row["id"],
            "case_id": row["case_id"],
            "actor_id": row["actor_id"],
            "actor_role": row["actor_role"],
            "action": row["action"],
            "reason": row["reason"],
            "detail": loads(row["detail"]) if row["detail"] else None,
            "from_state": row["from_state"],
            "to_state": row["to_state"],
            "created_at": row["created_at"],
        }

    def list_audit(self, actor: Actor, case_id: str) -> list[dict]:
        self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        rows = self.store.all(
            "SELECT * FROM audits WHERE case_id=? ORDER BY id DESC", (case_id,)
        )
        return [self._audit_view(r) for r in rows]

    # ================================================================
    # 租约式认领
    # ================================================================
    def claim_case(self, actor: Actor, case_id: str, data: dict) -> dict:
        self._require_role(actor, *_CONFIRM_ROLES)
        case = self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        if case["state"] not in ("待核验", "处置中"):
            raise StateConflict(f"状态[{case['state']}]不可认领，仅待核验/处置中可认领")
        ttl = data.get("ttl_seconds", LEASE_TTL_DEFAULT_SECONDS)
        try:
            ttl = float(ttl)
        except (TypeError, ValueError):
            raise ValidationError("ttl_seconds 须为数字")
        _require(0 <= ttl <= LEASE_TTL_MAX_SECONDS, f"租约时长须在 0~{LEASE_TTL_MAX_SECONDS} 秒")
        with self.store.tx():
            case = self._get_case_row(case_id)  # 事务内重读
            active = self._active_lease(case)
            now = timeutil.now_iso()
            if active and active["holder_id"] != actor.id:
                raise LeaseConflict(
                    f"案件正由 {active['holder_id']} 处置，租约至 {active['expires_at']}"
                )
            fencing = case["lease_fencing"] + 1
            token = uuid.uuid4().hex
            expires = timeutil.add_seconds(now, ttl)
            self.store.execute(
                "UPDATE cases SET lease_holder=?, lease_token=?, lease_fencing=?, lease_expires_at=? WHERE id=?",
                (actor.id, token, fencing, expires, case_id),
            )
            if case["assignee_id"] is None:
                self.store.execute(
                    "UPDATE cases SET assignee_id=? WHERE id=?", (actor.id, case_id)
                )
            self._audit(
                case_id, actor, "认领案件",
                reason="租约式认领，独占处置权",
                detail={"fencing": fencing, "ttl_seconds": ttl, "expires_at": expires},
            )
            self._touch(case_id)
        return {
            "case_id": case_id,
            "holder_id": actor.id,
            "lease_token": token,
            "fencing": fencing,
            "expires_at": expires,
        }

    def renew_lease(self, actor: Actor, case_id: str, data: dict) -> dict:
        case = self._get_case_row(case_id)
        token = data.get("lease_token")
        ttl = data.get("ttl_seconds", LEASE_TTL_DEFAULT_SECONDS)
        try:
            ttl = float(ttl)
        except (TypeError, ValueError):
            raise ValidationError("ttl_seconds 须为数字")
        with self.store.tx():
            case = self._get_case_row(case_id)
            self._require_lease(case, actor, token)
            expires = timeutil.add_seconds(timeutil.now_iso(), ttl)
            self.store.execute(
                "UPDATE cases SET lease_expires_at=? WHERE id=?", (expires, case_id)
            )
            self._audit(case_id, actor, "租约续期", detail={"expires_at": expires})
            self._touch(case_id)
        return {"case_id": case_id, "holder_id": actor.id, "expires_at": expires}

    def release_lease(self, actor: Actor, case_id: str, data: dict) -> dict:
        case = self._get_case_row(case_id)
        token = data.get("lease_token")
        with self.store.tx():
            case = self._get_case_row(case_id)
            self._require_lease(case, actor, token)
            self.store.execute(
                "UPDATE cases SET lease_holder=NULL, lease_token=NULL, lease_expires_at=NULL WHERE id=?",
                (case_id,),
            )
            self._audit(case_id, actor, "释放租约", reason=data.get("reason"))
            self._touch(case_id)
        return {"case_id": case_id, "released": True}

    # ================================================================
    # 状态流转（含转派前置的状态约束）
    # ================================================================
    def transition(self, actor: Actor, case_id: str, data: dict) -> dict:
        action = data.get("action")
        if action not in TRANSITIONS:
            raise ValidationError(f"未知流转动作：{action}，可选：{'、'.join(sorted(TRANSITIONS))}")
        spec = TRANSITIONS[action]
        self._require_role(actor, *sorted(spec["roles"]))
        reason = _require_reason(data.get("reason"))
        case = self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        with self.store.tx():
            case = self._get_case_row(case_id)
            from_state = case["state"]
            if from_state not in spec["from"]:
                raise StateConflict(
                    f"状态[{from_state}]不允许执行[{action}]，要求状态：{'、'.join(sorted(spec['from']))}"
                )
            if spec["lease"]:
                self._require_lease(case, actor, data.get("lease_token"))
            now = timeutil.now_iso()
            updates: dict = {"state": spec["to"]}
            detail: dict = {"action": action}

            if action == "triage":
                assignee = data.get("assignee_id")
                if assignee:
                    target = self.store.one("SELECT * FROM actors WHERE id=?", (assignee,))
                    _require(target is not None, f"承办人不存在：{assignee}")
                    _require(target["role"] in _CONFIRM_ROLES, "承办人须为监管人员或复核专家")
                    updates["assignee_id"] = assignee
                    detail["assignee_id"] = assignee
            elif action == "verify":
                if case["assignee_id"] is None:
                    updates["assignee_id"] = actor.id
            elif action == "decide":
                decision = data.get("decision")
                _require(decision in DECISIONS, f"处理决定须为：{'、'.join(DECISIONS)}")
                pending = self.store.one(
                    "SELECT 1 AS x FROM merge_suggestions WHERE status='待确认' AND source_case_id=? LIMIT 1",
                    (case_id,),
                )
                if pending:
                    raise DomainViolation("存在待确认的合并建议，须先处理再作决定")
                updates["decision"] = decision
                updates["decided_at"] = now
                detail["decision"] = decision
            elif action == "archive":
                active_measure = self.store.one(
                    "SELECT 1 AS x FROM measures WHERE case_id=? AND status='生效中' LIMIT 1",
                    (case_id,),
                )
                if active_measure:
                    raise DomainViolation("存在生效中的临时措施，须先解除再归档")
                pending = self.store.one(
                    "SELECT 1 AS x FROM merge_suggestions WHERE status='待确认' AND source_case_id=? LIMIT 1",
                    (case_id,),
                )
                if pending:
                    raise DomainViolation("存在待确认的合并建议，须先处理再归档")
                updates["archived_at"] = now
                updates["lease_holder"] = None
                updates["lease_token"] = None
                updates["lease_expires_at"] = None
            elif action == "reopen":
                # 结案复开：重新计时、重置延期额度、重新初评
                updates.update(
                    {
                        "cycle_started_at": now,
                        "decision": None,
                        "decided_at": None,
                        "archived_at": None,
                        "extension_count": 0,
                        "extension_days": 0,
                        "reopened_count": case["reopened_count"] + 1,
                        "lease_holder": None,
                        "lease_token": None,
                        "lease_expires_at": None,
                    }
                )
                detail["reopened_count"] = case["reopened_count"] + 1

            if action == "reopen":
                updates["due_at"] = self._due_at(now, case["priority"], 0)
            set_clause = ", ".join(f"{k}=?" for k in updates)
            self.store.execute(
                f"UPDATE cases SET {set_clause} WHERE id=?", (*updates.values(), case_id)
            )
            self._audit(
                case_id, actor, f"状态流转:{action}",
                reason=reason, detail=detail,
                from_state=from_state, to_state=spec["to"],
            )
            if action == "reopen":
                self._assess_priority(case_id)
            self._touch(case_id)
        return self.get_case(actor, case_id)

    # ================================================================
    # 转派 / 拆分
    # ================================================================
    def transfer(self, actor: Actor, case_id: str, data: dict) -> dict:
        self._require_role(actor, *_CONFIRM_ROLES)
        reason = _require_reason(data.get("reason"))
        to_id = data.get("to_actor_id")
        target = self.store.one("SELECT * FROM actors WHERE id=?", (to_id or "",))
        _require(target is not None, f"接收人不存在：{to_id}")
        _require(target["role"] in _CONFIRM_ROLES, "接收人须为监管人员或复核专家")
        case = self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        with self.store.tx():
            case = self._get_case_row(case_id)
            if case["state"] not in ("待核验", "处置中"):
                raise StateConflict(f"状态[{case['state']}]不可转派，仅待核验/处置中可转派")
            _require(case["assignee_id"] != to_id, "接收人已是当前承办人")
            active = self._active_lease(case)
            if active:
                # 有有效租约时：持约人本人转派（校验令牌），或复核专家监督转派
                if actor.role == "复核专家" and actor.id != active["holder_id"]:
                    pass
                else:
                    self._require_lease(case, actor, data.get("lease_token"))
            elif actor.id != case["assignee_id"] and actor.role != "复核专家":
                raise Forbidden("仅承办人或复核专家可转派")
            from_assignee = case["assignee_id"]
            self.store.execute(
                "UPDATE cases SET assignee_id=?, lease_holder=NULL, lease_token=NULL, "
                "lease_expires_at=NULL WHERE id=?",
                (to_id, case_id),
            )
            self._audit(
                case_id, actor, "转派案件",
                reason=reason,
                detail={"from_assignee": from_assignee, "to_assignee": to_id},
            )
            self._touch(case_id)
        return self.get_case(actor, case_id)

    def split_case(self, actor: Actor, case_id: str, data: dict) -> dict:
        self._require_role(actor, *_CONFIRM_ROLES)
        reason = _require_reason(data.get("reason"))
        title = (data.get("title") or "").strip()
        _require(bool(title), "拆分后的子案件标题不能为空")
        clue_ids = list(data.get("clue_ids") or [])
        subject_ids = list(data.get("subject_ids") or [])
        evidence_ids = list(data.get("evidence_ids") or [])
        _require(bool(clue_ids), "拆分须至少移出一条线索（clue_ids）")
        case = self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        with self.store.tx():
            case = self._get_case_row(case_id)
            if case["state"] not in ACTIVE_STATES:
                raise StateConflict(f"状态[{case['state']}]不可拆分")
            if case["state"] == "处置中":
                self._require_lease(case, actor, data.get("lease_token"))
            owned_clues = {
                r["clue_id"]
                for r in self.store.all("SELECT clue_id FROM case_clues WHERE case_id=?", (case_id,))
            }
            move_clues = set(clue_ids)
            _require(move_clues <= owned_clues, "存在不属于本案件的线索")
            _require(bool(owned_clues - move_clues), "母案件须至少保留一条线索")
            owned_subjects = {
                r["subject_id"]
                for r in self.store.all("SELECT subject_id FROM case_subjects WHERE case_id=?", (case_id,))
            }
            _require(set(subject_ids) <= owned_subjects, "存在不属于本案件的主体")
            owned_evidence = {
                r["id"] for r in self.store.all("SELECT id FROM evidence WHERE case_id=?", (case_id,))
            }
            _require(set(evidence_ids) <= owned_evidence, "存在不属于本案件的证据")

            now = timeutil.now_iso()
            child_id = self.store.next_id("CAS")
            self.store.execute(
                "INSERT INTO cases(id, title, state, priority, priority_status, rule_version, "
                "assignee_id, org_id, decision, registered_at, cycle_started_at, due_at, "
                "parent_id, created_at, updated_at) "
                "VALUES (?, ?, '登记', '中', '待确认', 0, NULL, ?, NULL, ?, ?, ?, ?, ?, ?)",
                (child_id, title, case["org_id"], now, now, self._due_at(now, "中", 0), case_id, now, now),
            )
            for cid in move_clues:
                self.store.execute(
                    "UPDATE case_clues SET case_id=? WHERE clue_id=?", (child_id, cid)
                )
                self.store.execute("UPDATE clues SET case_id=? WHERE id=?", (child_id, cid))
            for sid in subject_ids:
                self.store.execute(
                    "INSERT OR IGNORE INTO case_subjects(case_id, subject_id) VALUES (?, ?)",
                    (child_id, sid),
                )
                self.store.execute(
                    "DELETE FROM case_subjects WHERE case_id=? AND subject_id=?", (case_id, sid)
                )
            for eid in evidence_ids:
                self.store.execute("UPDATE evidence SET case_id=? WHERE id=?", (child_id, eid))
            detail = {
                "child_case_id": child_id,
                "moved_clues": sorted(move_clues),
                "moved_subjects": sorted(subject_ids),
                "moved_evidence": sorted(evidence_ids),
            }
            self._audit(case_id, actor, "拆分案件", reason=reason, detail=detail)
            self._audit(
                child_id, actor, "拆分自建",
                reason=reason,
                detail={"parent_case_id": case_id, **detail},
                to_state="登记",
            )
            self._assess_priority(case_id)
            self._assess_priority(child_id)
            self._touch(case_id)
            self._touch(child_id)
        return {
            "parent": self.get_case(actor, case_id),
            "child": self.get_case(actor, child_id),
        }

    # ================================================================
    # 临时措施
    # ================================================================
    def impose_measure(self, actor: Actor, case_id: str, data: dict) -> dict:
        self._require_role(actor, *_CONFIRM_ROLES)
        mtype = data.get("type")
        _require(mtype in MEASURE_TYPES, f"临时措施类型须为：{'、'.join(MEASURE_TYPES)}")
        reason = _require_reason(data.get("reason"))
        case = self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        with self.store.tx():
            case = self._get_case_row(case_id)
            if case["state"] != "处置中":
                raise StateConflict("仅处置中案件可采取临时措施")
            self._require_lease(case, actor, data.get("lease_token"))
            measure_id = self.store.next_id("MEA")
            now = timeutil.now_iso()
            self.store.execute(
                "INSERT INTO measures(id, case_id, type, note, status, imposed_by, imposed_at) "
                "VALUES (?, ?, ?, ?, '生效中', ?, ?)",
                (measure_id, case_id, mtype, data.get("note"), actor.id, now),
            )
            self._audit(
                case_id, actor, "采取临时措施",
                reason=reason,
                detail={"measure_id": measure_id, "type": mtype, "note": data.get("note")},
            )
            self._touch(case_id)
        row = self.store.one("SELECT * FROM measures WHERE id=?", (measure_id,))
        return row

    def lift_measure(self, actor: Actor, case_id: str, measure_id: str, data: dict) -> dict:
        self._require_role(actor, *_CONFIRM_ROLES)
        reason = _require_reason(data.get("reason"))
        case = self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        measure = self.store.one(
            "SELECT * FROM measures WHERE id=? AND case_id=?", (measure_id, case_id)
        )
        _require(measure is not None, f"临时措施不存在：{measure_id}")
        with self.store.tx():
            case = self._get_case_row(case_id)
            self._require_lease(case, actor, data.get("lease_token"))
            if measure["status"] != "生效中":
                raise StateConflict("该措施已解除")
            now = timeutil.now_iso()
            self.store.execute(
                "UPDATE measures SET status='已解除', lifted_by=?, lifted_at=?, lift_reason=? WHERE id=?",
                (actor.id, now, reason, measure_id),
            )
            self._audit(
                case_id, actor, "解除临时措施",
                reason=reason,
                detail={"measure_id": measure_id, "type": measure["type"]},
            )
            self._touch(case_id)
        return self.store.one("SELECT * FROM measures WHERE id=?", (measure_id,))

    # ================================================================
    # 延期
    # ================================================================
    def request_extension(self, actor: Actor, case_id: str, data: dict) -> dict:
        self._require_role(actor, *_CONFIRM_ROLES)
        reason = _require_reason(data.get("reason"))
        try:
            days = int(data.get("days"))
        except (TypeError, ValueError):
            raise ValidationError("延期天数须为整数")
        _require(1 <= days <= MAX_EXTENSION_DAYS, f"单次延期须为 1~{MAX_EXTENSION_DAYS} 天")
        case = self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        with self.store.tx():
            case = self._get_case_row(case_id)
            if case["state"] not in ("待核验", "处置中"):
                raise StateConflict(f"状态[{case['state']}]不可申请延期")
            self._require_lease(case, actor, data.get("lease_token"))
            if case["extension_count"] >= MAX_EXTENSIONS_PER_CYCLE:
                raise DomainViolation(f"每个办理周期最多延期 {MAX_EXTENSIONS_PER_CYCLE} 次")
            pending = self.store.one(
                "SELECT 1 AS x FROM extensions WHERE case_id=? AND status='待审批' LIMIT 1",
                (case_id,),
            )
            if pending:
                raise StateConflict("已存在待审批的延期申请")
            ext_id = self.store.next_id("EXT")
            self.store.execute(
                "INSERT INTO extensions(id, case_id, days, reason, status, requested_by, created_at) "
                "VALUES (?, ?, ?, ?, '待审批', ?, ?)",
                (ext_id, case_id, days, reason, actor.id, timeutil.now_iso()),
            )
            self._audit(
                case_id, actor, "申请延期",
                reason=reason,
                detail={"extension_id": ext_id, "days": days},
            )
            self._touch(case_id)
        return self.store.one("SELECT * FROM extensions WHERE id=?", (ext_id,))

    def decide_extension(self, actor: Actor, case_id: str, ext_id: str, data: dict) -> dict:
        self._require_role(actor, "复核专家")
        reason = _require_reason(data.get("reason"))
        approve = bool(data.get("approve"))
        case = self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        with self.store.tx():
            case = self._get_case_row(case_id)
            ext = self.store.one(
                "SELECT * FROM extensions WHERE id=? AND case_id=?", (ext_id, case_id)
            )
            _require(ext is not None, f"延期申请不存在：{ext_id}")
            if ext["status"] != "待审批":
                raise StateConflict("该延期申请已审批")
            now = timeutil.now_iso()
            self.store.execute(
                "UPDATE extensions SET status=?, decided_by=?, decided_at=?, decision_reason=? WHERE id=?",
                ("已批准" if approve else "已拒绝", actor.id, now, reason, ext_id),
            )
            if approve:
                new_count = case["extension_count"] + 1
                new_days = case["extension_days"] + ext["days"]
                self.store.execute(
                    "UPDATE cases SET extension_count=?, extension_days=?, due_at=? WHERE id=?",
                    (
                        new_count,
                        new_days,
                        self._due_at(case["cycle_started_at"], case["priority"], new_days),
                        case_id,
                    ),
                )
            self._audit(
                case_id, actor, "审批延期",
                reason=reason,
                detail={"extension_id": ext_id, "approve": approve, "days": ext["days"]},
            )
            self._touch(case_id)
        return self.store.one("SELECT * FROM extensions WHERE id=?", (ext_id,))

    # ================================================================
    # 证据
    # ================================================================
    def _insert_evidence(self, actor: Actor, case_id: str, data: dict) -> str:
        kind = data.get("kind")
        _require(kind in EVIDENCE_KINDS, f"证据种类须为：{'、'.join(EVIDENCE_KINDS)}")
        content = data.get("content") or ""
        _require(bool(content.strip()), "证据内容不能为空")
        try:
            sensitivity = int(data.get("sensitivity", 2))
        except (TypeError, ValueError):
            raise ValidationError("敏感级别须为 1~4 的整数")
        _require(1 <= sensitivity <= 4, "敏感级别须为 1~4 的整数")
        if actor.role == "机构合规员":
            _require(sensitivity <= 3, "机构合规员最高可标记敏感级（3）证据")
        ev_id = self.store.next_id("EVD")
        self.store.execute(
            "INSERT INTO evidence(id, case_id, kind, filename, content, sensitivity, sha256, "
            "uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ev_id,
                case_id,
                kind,
                data.get("filename"),
                content,
                sensitivity,
                fingerprint.content_hash(content),
                actor.id,
                timeutil.now_iso(),
            ),
        )
        return ev_id

    def add_evidence(self, actor: Actor, case_id: str, data: dict) -> dict:
        self._require_role(actor, "机构合规员", *_CONFIRM_ROLES)
        case = self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        with self.store.tx():
            case = self._get_case_row(case_id)
            if case["state"] not in ACTIVE_STATES:
                raise StateConflict(f"状态[{case['state']}]不可补充证据")
            if case["state"] == "处置中":
                self._require_lease(case, actor, data.get("lease_token"))
            ev_id = self._insert_evidence(actor, case_id, data)
            self._audit(
                case_id, actor, "补充证据",
                detail={"evidence_id": ev_id, "kind": data.get("kind"), "sensitivity": data.get("sensitivity", 2)},
            )
            self._assess_priority(case_id)  # 敏感证据可能影响风险级别
            self._touch(case_id)
        case = self._get_case_row(case_id)
        ev = self.store.one("SELECT * FROM evidence WHERE id=?", (ev_id,))
        return redaction.evidence_view(actor.role, ev)

    def list_evidence(self, actor: Actor, case_id: str) -> dict:
        self._get_case_row(case_id)
        self._require_visible(actor, case_id)
        rows = self.store.all(
            "SELECT * FROM evidence WHERE case_id=? ORDER BY created_at", (case_id,)
        )
        views, hidden = redaction.redact_evidence_list(actor.role, rows)
        return {"items": views, "hidden_count": hidden}

    # ================================================================
    # 合并建议：确认 / 拒绝
    # ================================================================
    def list_merge_suggestions(self, actor: Actor, query: dict) -> list[dict]:
        self._require_role(actor, *_CONFIRM_ROLES)
        status = query.get("status")
        if status:
            rows = self.store.all(
                "SELECT * FROM merge_suggestions WHERE status=? ORDER BY created_at DESC", (status,)
            )
        else:
            rows = self.store.all("SELECT * FROM merge_suggestions ORDER BY created_at DESC")
        return [self._suggestion_view(r) for r in rows]

    def _get_suggestion(self, suggestion_id: str) -> dict:
        row = self.store.one("SELECT * FROM merge_suggestions WHERE id=?", (suggestion_id,))
        if row is None:
            raise NotFound(f"合并建议不存在：{suggestion_id}")
        return row

    @staticmethod
    def _suggestion_view(r: dict) -> dict:
        return {
            "id": r["id"],
            "clue_id": r["clue_id"],
            "source_case_id": r["source_case_id"],
            "target_case_id": r["target_case_id"],
            "score": r["score"],
            "signals": loads(r["signals"]),
            "status": r["status"],
            "created_at": r["created_at"],
            "decided_by": r["decided_by"],
            "decided_at": r["decided_at"],
            "decision_reason": r["decision_reason"],
        }

    def confirm_merge(self, actor: Actor, suggestion_id: str, data: dict) -> dict:
        """确认合并：来源案件的线索/主体/证据并入目标案件，来源案件以“并入”结案归档。"""
        self._require_role(actor, *_CONFIRM_ROLES)
        reason = _require_reason(data.get("reason"))
        with self.store.tx():
            sug = self._get_suggestion(suggestion_id)
            if sug["status"] != "待确认":
                raise StateConflict("该合并建议已处理")
            source = self._get_case_row(sug["source_case_id"])
            target = self._get_case_row(sug["target_case_id"])
            if source["state"] not in ACTIVE_STATES:
                raise StateConflict(f"来源案件状态[{source['state']}]不可并入")
            if target["state"] not in ACTIVE_STATES:
                raise StateConflict(f"目标案件状态[{target['state']}]不可接收并入")
            now = timeutil.now_iso()
            # 迁移线索 / 主体 / 证据
            self.store.execute(
                "UPDATE case_clues SET case_id=? WHERE case_id=?", (target["id"], source["id"])
            )
            self.store.execute(
                "UPDATE clues SET case_id=? WHERE case_id=?", (target["id"], source["id"])
            )
            for row in self.store.all(
                "SELECT subject_id FROM case_subjects WHERE case_id=?", (source["id"],)
            ):
                self.store.execute(
                    "INSERT OR IGNORE INTO case_subjects(case_id, subject_id) VALUES (?, ?)",
                    (target["id"], row["subject_id"]),
                )
            self.store.execute("DELETE FROM case_subjects WHERE case_id=?", (source["id"],))
            self.store.execute(
                "UPDATE evidence SET case_id=? WHERE case_id=?", (target["id"], source["id"])
            )
            # 来源案件合并关闭
            self.store.execute(
                "UPDATE cases SET state='已归档', decision=?, archived_at=?, "
                "lease_holder=NULL, lease_token=NULL, lease_expires_at=NULL WHERE id=?",
                (f"并入案件 {target['id']}", now, source["id"]),
            )
            self.store.execute(
                "UPDATE merge_suggestions SET status='已确认', decided_by=?, decided_at=?, "
                "decision_reason=? WHERE id=?",
                (actor.id, now, reason, suggestion_id),
            )
            # 关联来源案件的其他待确认建议一并失效
            for other in self.store.all(
                "SELECT id FROM merge_suggestions WHERE status='待确认' AND "
                "(source_case_id=? OR target_case_id=?) AND id!=?",
                (source["id"], source["id"], suggestion_id),
            ):
                self.store.execute(
                    "UPDATE merge_suggestions SET status='已拒绝', decided_by='system', decided_at=?, "
                    "decision_reason='相关案件已合并处理' WHERE id=?",
                    (now, other["id"]),
                )
            self._audit(
                source["id"], actor, "合并关闭",
                reason=reason,
                detail={"suggestion_id": suggestion_id, "merged_into": target["id"]},
                from_state=source["state"], to_state="已归档",
            )
            self._audit(
                target["id"], actor, "并入线索",
                reason=reason,
                detail={"suggestion_id": suggestion_id, "merged_from": source["id"]},
            )
            self._assess_priority(target["id"])  # 多渠道汇聚后重新初评
            self._touch(source["id"])
            self._touch(target["id"])
        return {
            "suggestion": self._suggestion_view(self._get_suggestion(suggestion_id)),
            "source_case": self.get_case(actor, source["id"]),
            "target_case": self.get_case(actor, target["id"]),
        }

    def reject_merge(self, actor: Actor, suggestion_id: str, data: dict) -> dict:
        self._require_role(actor, *_CONFIRM_ROLES)
        reason = _require_reason(data.get("reason"))
        with self.store.tx():
            sug = self._get_suggestion(suggestion_id)
            if sug["status"] != "待确认":
                raise StateConflict("该合并建议已处理")
            now = timeutil.now_iso()
            self.store.execute(
                "UPDATE merge_suggestions SET status='已拒绝', decided_by=?, decided_at=?, "
                "decision_reason=? WHERE id=?",
                (actor.id, now, reason, suggestion_id),
            )
            self._audit(
                sug["source_case_id"], actor, "拒绝合并建议",
                reason=reason,
                detail={"suggestion_id": suggestion_id, "target_case_id": sug["target_case_id"]},
            )
            self._touch(sug["source_case_id"])
        return self._suggestion_view(self._get_suggestion(suggestion_id))

    # ================================================================
    # 风险规则集（版本化）
    # ================================================================
    def list_rules(self, actor: Actor) -> dict:
        version, rules = self._current_rules()
        return {
            "version": version,
            "rules": [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "kind": r["kind"],
                    "params": r["params"],
                    "points": r["points"],
                    "enabled": bool(r["enabled"]),
                }
                for r in rules
            ],
        }

    def replace_rules(self, actor: Actor, data: dict) -> dict:
        """整体替换规则集并递增版本；历史评估仍引用旧版本号，可追溯。"""
        self._require_role(actor, "复核专家")
        rules = data.get("rules")
        _require(isinstance(rules, list) and bool(rules), "规则集不能为空")
        for r in rules:
            _require(bool((r.get("name") or "").strip()), "规则名称不能为空")
            _require(r.get("kind") in risk.RULE_KINDS, f"规则类型须为：{'、'.join(risk.RULE_KINDS)}")
            _require(isinstance(r.get("params", {}), dict), "规则参数须为对象")
            try:
                points = int(r.get("points"))
            except (TypeError, ValueError):
                raise ValidationError("规则分值须为整数")
            _require(1 <= points <= 100, "规则分值须为 1~100")
            if r["kind"] == "keyword":
                _require(bool(r["params"].get("words")), "keyword 规则须含 words 列表")
            if r["kind"] == "channel":
                _require(r["params"].get("channel") in CHANNELS, "channel 规则须含合法渠道")
        with self.store.tx():
            version = int(self.store.get_meta("risk_rule_version") or 0) + 1
            for i, r in enumerate(rules, start=1):
                self.store.execute(
                    "INSERT INTO risk_rules(id, version, name, kind, params, points, enabled) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        f"RUL-V{version}-{i:03d}",
                        version,
                        r["name"].strip(),
                        r["kind"],
                        dumps(r.get("params", {})),
                        int(r["points"]),
                        1 if r.get("enabled", True) else 0,
                    ),
                )
            self.store.set_meta("risk_rule_version", str(version))
        return self.list_rules(actor)
