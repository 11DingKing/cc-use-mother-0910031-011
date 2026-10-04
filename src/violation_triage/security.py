"""密码哈希与令牌生成（标准库实现）。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets


def hash_password(password: str, *, salt: bytes | None = None, iterations: int = 200_000) -> str:
    """返回 ``pbkdf2_sha256$iterations$salt_b64$hash_b64`` 形式的哈希串。"""
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iter_text, salt_b64, hash_b64 = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iter_text)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest, expected)


def new_token() -> str:
    return secrets.token_urlsafe(32)
