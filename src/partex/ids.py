"""Canonical JSON encoding and deterministic content-hash IDs — PLAN §12.

Every byte-determinism claim depends on the single canonical JSON encoding defined here.
"""

import hashlib
import json
from typing import Any

from .models import Engagement, Evidence


def canonical_json(obj: Any) -> bytes:
    """Return the canonical JSON byte encoding of *obj*.

    Properties:
    - keys sorted lexicographically
    - ``ensure_ascii=True`` (no raw Unicode escapes)
    - compact separators ``(',', ':')`` (no trailing whitespace)
    - no trailing newline (callers add it for file output when applicable)

    This is the single encoding every hash and byte-determinism claim depends on.
    """
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


# ── Content-addressable IDs (§12) ─────────────────────────────────────────────


def evidence_id(evidence: Evidence) -> str:
    """Return ``ev_`` + sha256 over the canonical JSON of ``kind`` + content only.

    Excludes ``id``, ``source``, and ``secret_fields`` so the same exchange hashes
    identically whether captured live or re-imported from a bundle.
    """
    # Extract only the content-bearing fields (kind + the payload)
    d = evidence.model_dump(mode='json', exclude={'id', 'source', 'secret_fields', 'tls_verified'})
    return 'ev_' + sha256_hex(canonical_json(d))[:16]


def finding_id(check_id: str, subject: str, title: str, evidence_ids: list[str]) -> str:
    """Return ``fn_`` + sha256 over ``check_id``, ``subject``, ``title``, and sorted evidence IDs.

    ``subject`` keeps findings apart that share a title and evidence (two cookies on one
    response); identical inputs are the same finding and the engine merges them.
    """
    payload = check_id + '\0' + subject + '\0' + title + '\0' + '\0'.join(sorted(evidence_ids))
    return 'fn_' + sha256_hex(payload.encode())[:16]


def verification_id(finding_id: str, requests: list[str]) -> str:
    """Return ``vf_`` + sha256 over ``finding_id`` and the canonical request set."""
    payload = finding_id + '\0' + canonical_json(requests).decode()
    return 'vf_' + sha256_hex(payload.encode())[:16]


def engagement_id(engagement: Engagement) -> str:
    """Return ``eng_`` + sha256 over the canonical JSON of the validated engagement manifest.

    Hashing the validated model (not the file bytes) makes whitespace, key order, and defaulted
    fields irrelevant: two manifests that validate to the same engagement share one ID.
    """
    return 'eng_' + sha256_hex(canonical_json(engagement.model_dump(mode='json')))[:16]


def normalized_operation_key(method: str, path_template: str) -> str:
    """Return the canonical operation key: uppercase method + contract path template.

    Example: ``('get', '/api/users/{id}')`` → ``'GET /api/users/{id}'``

    Passive checks use this instead of raw observed paths so finding IDs survive
    bundle revisions and route reordering.
    """
    return f'{method.upper()} {path_template}'
