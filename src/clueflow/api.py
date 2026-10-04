"""HTTP API：基于标准库 http.server 的 JSON 接口。

认证：除公开路由外，所有请求须携带 `X-Actor-Id` 请求头；角色与所属机构以服务端
登记为准。租约令牌可放请求体 `lease_token` 字段。
错误格式：{"error": {"code": ..., "message": ...}}。
"""
from __future__ import annotations

import json
import re
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .errors import DomainError, NotFound, Unauthorized, ValidationError
from .services import ClueflowService


class Request:
    def __init__(self, method: str, path: str, query: dict, body: dict, actor):
        self.method = method
        self.path = path
        self.query = query
        self.body = body
        self.actor = actor


class Router:
    def __init__(self):
        self.routes: list[tuple[str, re.Pattern, object, bool]] = []

    def add(self, method: str, pattern: str, handler, public: bool = False):
        regex = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "$")
        self.routes.append((method, regex, handler, public))

    def dispatch(self, req: Request):
        for method, regex, handler, public in self.routes:
            if method != req.method:
                continue
            match = regex.match(req.path)
            if match:
                if not public and req.actor is None:
                    raise Unauthorized("缺少 X-Actor-Id 请求头")
                return handler(req, **match.groupdict())
        raise NotFound(f"接口不存在：{req.method} {req.path}")


def build_router(service: ClueflowService) -> Router:
    r = Router()
    ok = lambda obj, status=200: (status, obj)  # noqa: E731

    r.add("GET", "/", lambda req: ok({
        "service": "违规线索分流处置",
        "docs": "见 README.md",
        "endpoints": [route[1].pattern for route in r.routes],
    }), public=True)
    r.add("GET", "/health", lambda req: ok({"status": "ok"}), public=True)
    r.add("GET", "/meta", lambda req: ok(service.meta()), public=True)
    r.add("GET", "/actors", lambda req: ok({"items": service.list_actors()}), public=True)

    r.add("POST", "/clues", lambda req: ok(service.register_clue(req.actor, req.body), 201))
    r.add("GET", "/clues", lambda req: ok({"items": service.list_clues(req.actor, req.query)}))
    r.add("GET", "/clues/{clue_id}", lambda req, clue_id: ok(service.get_clue(req.actor, clue_id)))

    r.add("GET", "/cases", lambda req: ok(service.list_cases(req.actor, req.query)))
    r.add("GET", "/cases/{case_id}", lambda req, case_id: ok(service.get_case(req.actor, case_id)))
    r.add("POST", "/cases/{case_id}/claim", lambda req, case_id: ok(service.claim_case(req.actor, case_id, req.body)))
    r.add("POST", "/cases/{case_id}/renew", lambda req, case_id: ok(service.renew_lease(req.actor, case_id, req.body)))
    r.add("POST", "/cases/{case_id}/release", lambda req, case_id: ok(service.release_lease(req.actor, case_id, req.body)))
    r.add("POST", "/cases/{case_id}/transitions", lambda req, case_id: ok(service.transition(req.actor, case_id, req.body)))
    r.add("POST", "/cases/{case_id}/transfer", lambda req, case_id: ok(service.transfer(req.actor, case_id, req.body)))
    r.add("POST", "/cases/{case_id}/split", lambda req, case_id: ok(service.split_case(req.actor, case_id, req.body), 201))
    r.add("POST", "/cases/{case_id}/measures", lambda req, case_id: ok(service.impose_measure(req.actor, case_id, req.body), 201))
    r.add("POST", "/cases/{case_id}/measures/{measure_id}/lift",
          lambda req, case_id, measure_id: ok(service.lift_measure(req.actor, case_id, measure_id, req.body)))
    r.add("POST", "/cases/{case_id}/extensions", lambda req, case_id: ok(service.request_extension(req.actor, case_id, req.body), 201))
    r.add("POST", "/cases/{case_id}/extensions/{ext_id}/decide",
          lambda req, case_id, ext_id: ok(service.decide_extension(req.actor, case_id, ext_id, req.body)))
    r.add("POST", "/cases/{case_id}/evidence", lambda req, case_id: ok(service.add_evidence(req.actor, case_id, req.body), 201))
    r.add("GET", "/cases/{case_id}/evidence", lambda req, case_id: ok(service.list_evidence(req.actor, case_id)))
    r.add("GET", "/cases/{case_id}/audit", lambda req, case_id: ok({"items": service.list_audit(req.actor, case_id)}))
    r.add("POST", "/cases/{case_id}/priority/confirm", lambda req, case_id: ok(service.confirm_priority(req.actor, case_id, req.body)))

    r.add("GET", "/merge-suggestions", lambda req: ok({"items": service.list_merge_suggestions(req.actor, req.query)}))
    r.add("POST", "/merge-suggestions/{sid}/confirm", lambda req, sid: ok(service.confirm_merge(req.actor, sid, req.body)))
    r.add("POST", "/merge-suggestions/{sid}/reject", lambda req, sid: ok(service.reject_merge(req.actor, sid, req.body)))

    r.add("GET", "/risk-rules", lambda req: ok(service.list_rules(req.actor)))
    r.add("PUT", "/risk-rules", lambda req: ok(service.replace_rules(req.actor, req.body)))

    r.add("POST", "/subjects", lambda req: ok(service.create_subject(req.actor, req.body), 201))
    r.add("GET", "/subjects", lambda req: ok({"items": service.list_subjects(req.actor)}))
    return r


def make_handler(service: ClueflowService):
    router = build_router(service)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # 静默访问日志
            pass

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_PUT(self):
            self._handle("PUT")

        def _handle(self, method: str):
            try:
                req = self._build_request(method)
                status, obj = router.dispatch(req)
            except DomainError as exc:
                status, obj = exc.status, {"error": {"code": exc.code, "message": str(exc)}}
            except Exception:  # pragma: no cover - 兜底
                traceback.print_exc()
                status, obj = 500, {"error": {"code": "INTERNAL", "message": "服务器内部错误"}}
            payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _build_request(self, method: str) -> Request:
            parts = urllib.parse.urlsplit(self.path)
            query = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query).items()}
            body: dict = {}
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                raw = self.rfile.read(length)
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    raise ValidationError("请求体须为合法 JSON")
                if not isinstance(parsed, dict):
                    raise ValidationError("请求体须为 JSON 对象")
                body = parsed
            actor = None
            actor_id = self.headers.get("X-Actor-Id")
            if actor_id:
                actor = service.authenticate(actor_id)
            return Request(method, parts.path, query, body, actor)

    return Handler


def create_server(service: ClueflowService, host: str = "127.0.0.1", port: int = 8080):
    return ThreadingHTTPServer((host, port), make_handler(service))
