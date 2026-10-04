"""来源指纹与相似度计算。

同一事件经多渠道重复登记时，依靠两类信号识别：
- 精确指纹：渠道 + 涉及主体标识 + 归一化内容 + 事发日期的哈希，完全一致即高度疑似重复；
- 相似度：内容词元 Jaccard 相似度与主体重合度的加权得分。
"""
from __future__ import annotations

import hashlib
import re
import unicodedata

_CJK = re.compile(r"[一-鿿]")
_KEEP = re.compile(r"[0-9a-zA-Z一-鿿]")
_LATIN = re.compile(r"[a-z0-9]+")


def normalize_text(text: str | None) -> str:
    """归一化文本：兼容形归一、小写、去除标点与空白，仅保留字母数字与汉字。"""
    text = unicodedata.normalize("NFKC", text or "").lower()
    return "".join(ch for ch in text if _KEEP.match(ch))


def content_tokens(text: str | None) -> set[str]:
    """提取内容词元：长度≥2的英文/数字词 + 汉字二元组（单字保留）。"""
    text = unicodedata.normalize("NFKC", text or "").lower()
    tokens: set[str] = set()
    tokens.update(w for w in _LATIN.findall(text) if len(w) >= 2)
    cjk_only = "".join(ch if _CJK.match(ch) else " " for ch in text)
    for seg in cjk_only.split():
        if len(seg) == 1:
            tokens.add(seg)
        else:
            tokens.update(seg[i : i + 2] for i in range(len(seg) - 1))
    return tokens


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def contact_hash(contact: str | None) -> str | None:
    """联系方式只存哈希，不落明文。"""
    norm = normalize_text(contact)
    if not norm:
        return None
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def source_fingerprint(
    channel: str,
    subject_identifiers: list[str],
    content: str,
    event_date: str | None,
) -> str:
    """来源指纹：同一事件同一渠道重复提交时保持稳定。"""
    base = "|".join(
        [
            channel,
            ",".join(sorted(subject_identifiers)),
            normalize_text(content),
            event_date or "",
        ]
    )
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:32]


def merge_score(
    fingerprint_match: bool,
    text_similarity: float,
    shared_subjects: int,
    total_subjects: int,
) -> float:
    """合并建议得分：精确指纹直接满分，否则内容相似度与主体重合度加权。"""
    if fingerprint_match:
        return 1.0
    subject_ratio = shared_subjects / total_subjects if total_subjects else 0.0
    return round(0.6 * text_similarity + 0.4 * subject_ratio, 4)
