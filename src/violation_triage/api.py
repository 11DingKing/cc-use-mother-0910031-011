"""HTTP 接口：标准库 http.server，Bearer 令牌认证，按角色裁剪。"""
from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .config import ROLES, SENSITIVITY_LEVELS, Settings
from .errors import DomainError
from .service import TriageService


class Api:
    """保存服务实例与路由表，供 Handler 无状态分发。"""

    def __init__(self, service: TriageService) -> None:
        self.service = service
        # (method, compiled_path) -> (handler_name, kwargs 模板)
        self.routes: list[tuple[str, re.Pattern[str], str]] = [
            ("GET", re.compile(r"^/healthz$"), "health"),
            ("POST", re.compile(r"^/api/auth/login$"), "login"),
            ("POST", re.compile(r"^/api/auth/logout$"), "logout"),
            ("GET", re.compile(r"^/api/me$"), "me"),
            ("GET", re.compile(r"^/api/roles$"), "roles"),

            ("POST", re.compile(r"^/api/users$"), "create_user"),

            ("GET", re.compile(r"^/api/rules/versions$"), "rule_versions"),
            ("POST", re.compile(r"^/api/rules/versions$"), "publish_rules"),
            ("GET", re.compile(r"^/api/rules$"), "get_rules"),

            ("POST", re.compile(r"^/api/clues$"), "register_clue"),
            ("GET", re.compile(r"^/api/clues$"), "list_clues"),
            ("GET", re.compile(r"^/api/clues/(?P<ref>[^/]+)$"), "clue_detail"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/evidence$"), "add_evidence"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/rescan-duplicates$"), "rescan_duplicates"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/priority$"), "confirm_priority"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/rescale-risk$"), "rescale_risk"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/accept$"), "accept_clue"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/claim$"), "claim"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/renew-lease$"), "renew_lease"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/release$"), "release"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/assign$"), "assign"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/verify$"), "verify"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/split$"), "split"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/close$"), "close"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/archive$"), "archive"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/reopen$"), "reopen"),
            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/measures$"), "create_measure"),

            ("POST", re.compile(r"^/api/measures/(?P<id>\d+)/lift$"), "lift_measure"),

            ("POST", re.compile(r"^/api/clues/(?P<ref>[^/]+)/extensions$"), "request_extension"),
            ("GET", re.compile(r"^/api/extensions$"), "list_extensions"),
            ("POST", re.compile(r"^/api/extensions/(?P<id>\d+)/decision$"), "decide_extension"),

            ("GET", re.compile(r"^/api/merge-suggestions$"), "list_merge"),
            ("POST", re.compile(r"^/api/merge-suggestions/(?P<id>\d+)/confirm$"), "confirm_merge"),
            ("POST", re.compile(r"^/api/merge-suggestions/(?P<id>\d+)/reject$"), "reject_merge"),

            ("GET", re.compile(r"^/api/audit$"), "audit"),
        ]


class Handler(BaseHTTPRequestHandler):
    server_version = "ViolationTriage/0.2"
    api: Api = None  # type: ignore[assignment]  由 make_server 注入

    # ---- 框架 --------------------------------------------------------------

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        import os
        import sys

        if os.environ.get("TRIAGE_QUIET"):
            return
        sys.stderr.write("[%s] %s - %s\n" % (self.log_date_time_string(), self.address_string(), fmt % args))

    def _send(self, payload, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            from .errors import ValidationError

            raise ValidationError("请求体不是合法 JSON")
        if not isinstance(value, dict):
            from .errors import ValidationError

            raise ValidationError("请求体必须是 JSON 对象")
        return value

    def _token(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return None

    def _current_user(self):
        return self.api.service.authenticate(self._token())

    def _dispatch(self, method: str) -> None:
        parts = urlsplit(self.path)
        path = parts.path
        if path != "/":
            path = path.rstrip("/") or "/"
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        for verb, pattern, handler_name in self.api.routes:
            if verb != method:
                continue
            match = pattern.match(path)
            if match:
                try:
                    payload = self._read_json() if method in ("POST", "PUT", "PATCH") else {}
                    user = None
                    if handler_name not in ("health", "login"):
                        user = self._current_user()
                    result = getattr(self, handler_name)(user, payload, query, **match.groupdict())
                except DomainError as exc:
                    self._send(exc.to_dict(), exc.status)
                    return
                except (ValueError, TypeError) as exc:
                    self._send({"error": "bad_request", "message": f"参数错误：{exc}"}, 400)
                    return
                except Exception:  # noqa: BLE001 - 兜底，避免断连
                    import logging
                    import traceback

                    logging.getLogger("violation_triage").error(traceback.format_exc())
                    self._send({"error": "internal", "message": "服务内部错误"}, 500)
                    return
                if result is None:
                    return
                body, status = result if isinstance(result, tuple) else (result, 200)
                self._send(body, status)
                return
        self._send({"error": "not_found", "message": f"无此接口：{method} {path}"}, 404)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    # ---- 处理器 ------------------------------------------------------------

    def health(self, user, payload, query):
        return {"status": "ok", "product": "违规线索分流处置"}

    def login(self, user, payload, query):
        return self.api.service.login(str(payload.get("username", "")), str(payload.get("password", "")))

    def logout(self, user, payload, query):
        self.api.service.logout(self._token() or "")
        return {"logged_out": True}

    def me(self, user, payload, query):
        return {"id": user["id"], "username": user["username"], "display_name": user["display_name"], "role": user["role"]}

    def roles(self, user, payload, query):
        from .config import ROLE_MAX_SENSITIVITY

        return {
            "roles": list(ROLES),
            "sensitivity_levels": list(SENSITIVITY_LEVELS),
            "role_max_sensitivity": ROLE_MAX_SENSITIVITY,
        }

    def create_user(self, user, payload, query):
        from .errors import PermissionError as Perm

        if user["role"] != "分流管理员":
            raise Perm("只有分流管理员可以创建账号")
        return self.api.service.create_user(
            str(payload.get("username", "")),
            str(payload.get("password", "")),
            str(payload.get("display_name", payload.get("username", ""))),
            str(payload.get("role", "")),
        )

    def rule_versions(self, user, payload, query):
        return {"versions": self.api.service.list_rule_versions(user)}

    def publish_rules(self, user, payload, query):
        return self.api.service.publish_rules(user, payload.get("rules", []), str(payload.get("note", "")))

    def get_rules(self, user, payload, query):
        version = int(query["version"]) if query.get("version") else None
        return self.api.service.get_rules(version)

    def register_clue(self, user, payload, query):
        result = self.api.service.register_clue(user, payload)
        return result, (200 if result.get("duplicate") else 201)

    def list_clues(self, user, payload, query):
        return self.api.service.list_clues(user, query)

    def clue_detail(self, user, payload, query, ref: str):
        return self.api.service.get_clue_detail(user, ref)

    def add_evidence(self, user, payload, query, ref: str):
        return self.api.service.add_evidence(user, ref, payload), 201

    def rescan_duplicates(self, user, payload, query, ref: str):
        return self.api.service.rescan_duplicates(user, ref)

    def confirm_priority(self, user, payload, query, ref: str):
        return self.api.service.confirm_priority(
            user, ref,
            str(payload.get("priority", "")),
            str(payload.get("reason", "")),
            payload.get("deadline_hours"),
        )

    def rescale_risk(self, user, payload, query, ref: str):
        return self.api.service.rescale_risk(user, ref)

    def accept_clue(self, user, payload, query, ref: str):
        return self.api.service.accept_clue(user, ref)

    def claim(self, user, payload, query, ref: str):
        return self.api.service.claim(user, ref)

    def renew_lease(self, user, payload, query, ref: str):
        return self.api.service.renew_lease(user, ref)

    def release(self, user, payload, query, ref: str):
        return self.api.service.release_clue(user, ref, str(payload.get("reason", "")))

    def assign(self, user, payload, query, ref: str):
        assignee = payload.get("assignee_id")
        if assignee is None:
            from .errors import ValidationError

            raise ValidationError("缺少 assignee_id")
        return self.api.service.assign(user, ref, int(assignee), str(payload.get("reason", "")))

    def verify(self, user, payload, query, ref: str):
        return self.api.service.verify_clue(user, ref, str(payload.get("note", "")))

    def split(self, user, payload, query, ref: str):
        return self.api.service.split_clue(user, ref, payload.get("children", [])), 201

    def close(self, user, payload, query, ref: str):
        return self.api.service.close_clue(user, ref, str(payload.get("decision", "")), str(payload.get("summary", "")))

    def archive(self, user, payload, query, ref: str):
        return self.api.service.archive_clue(user, ref)

    def reopen(self, user, payload, query, ref: str):
        return self.api.service.reopen_clue(user, ref, str(payload.get("reason", "")))

    def create_measure(self, user, payload, query, ref: str):
        return self.api.service.create_measure(user, ref, str(payload.get("measure_type", "")), str(payload.get("detail", ""))), 201

    def lift_measure(self, user, payload, query, id: str):
        return self.api.service.lift_measure(user, int(id), str(payload.get("reason", "")))

    def request_extension(self, user, payload, query, ref: str):
        return self.api.service.request_extension(user, ref, int(payload.get("hours", 0)), str(payload.get("reason", ""))), 201

    def list_extensions(self, user, payload, query):
        return {"items": self.api.service.list_extensions(user, query.get("status"))}

    def decide_extension(self, user, payload, query, id: str):
        return self.api.service.decide_extension(user, int(id), bool(payload.get("approve", False)), str(payload.get("comment", "")))

    def list_merge(self, user, payload, query):
        return {"items": self.api.service.list_merge_suggestions(user, query.get("status", "待确认"))}

    def confirm_merge(self, user, payload, query, id: str):
        return self.api.service.confirm_merge(user, int(id), str(payload.get("reason", "")))

    def reject_merge(self, user, payload, query, id: str):
        return self.api.service.reject_merge(user, int(id), str(payload.get("reason", "")))

    def audit(self, user, payload, query):
        limit = int(query.get("limit", "100"))
        return {"items": self.api.service.list_audit(user, query.get("clue"), limit)}


def make_server(settings: Settings, service: TriageService | None = None) -> ThreadingHTTPServer:
    service = service or TriageService(settings.db_path, lease_seconds=settings.lease_seconds)
    api = Api(service)

    class BoundHandler(Handler):
        pass

    BoundHandler.api = api
    httpd = ThreadingHTTPServer((settings.host, settings.port), BoundHandler)
    httpd.service = service  # type: ignore[attr-defined]
    return httpd
