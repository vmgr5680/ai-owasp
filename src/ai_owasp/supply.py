"""Part 4, LLM04:2026 Supply Chain.

A model file is code and data you did not write. Four checks you can run
before anything is loaded: what the file will import, whether it is the
exact file you approved, whether a suggested dependency really exists, and
what you are allowed to do with each component.
"""

from __future__ import annotations

import hashlib
import hmac
import pickletools
from datetime import date

# --- 1. What will this pickle import when it loads? ----------------------
SAFE_GLOBALS = {("collections", "OrderedDict"), ("builtins", "dict"),
                ("builtins", "list"), ("builtins", "float")}


def pickle_imports(data: bytes) -> list[tuple[str, str]]:
    """List every (module, name) the pickle will import, without loading
    it. Handles GLOBAL (protocol 0-3) and STACK_GLOBAL (protocol 4+)."""
    found, strings = [], []
    for op, arg, _ in pickletools.genops(data):
        if op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE"):
            strings.append(arg)
        elif op.name == "GLOBAL":
            module, name = arg.split(" ", 1)
            found.append((module, name))
        elif op.name == "STACK_GLOBAL":
            found.append((strings[-2], strings[-1]))
    return found


def scan_pickle(data: bytes) -> list[str]:
    return [f"{m}.{n}" for m, n in pickle_imports(data)
            if (m, n) not in SAFE_GLOBALS]


# --- 2. Is it the exact file we approved? --------------------------------
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_pinned(hub: dict, name: str, pinned_digest: str | None) -> str:
    blob = hub[name]
    if pinned_digest is None:
        return f"loaded by name (sha256 {sha256(blob)[:12]}...)"
    if sha256(blob) != pinned_digest:
        return (f"REFUSED: digest {sha256(blob)[:12]}... "
                f"!= pinned {pinned_digest[:12]}...")
    return f"loaded, digest matches {pinned_digest[:12]}..."


# --- signing proves origin and integrity, not safety ---------------------
def sign(key: bytes, data: bytes) -> str:
    # Stand-in for real artifact signing (Sigstore / OpenSSF model
    # signing use public-key signatures and a transparency log).
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify(key: bytes, data: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(key, data), signature)


# --- 3. Does the suggested package exist, and since when? ----------------
def check_dependency(name: str, registry: dict, today: date,
                     min_age_days: int = 90) -> str:
    entry = registry.get(name.lower())
    if entry is None:
        return "NOT ON REGISTRY: hallucinated? do not install"
    age = (today - date.fromisoformat(entry["first_seen"])).days
    if age < min_age_days:
        return f"SUSPICIOUS: first published {age} days ago"
    return f"ok (on the registry for over {min_age_days} days)"


# --- 4. An AI bill of materials with licences ----------------------------
COMMERCIAL_BLOCKERS = ("-nc", "noncommercial", "research-only")


def aibom(components: list[dict]) -> dict:
    """A CycloneDX-shaped inventory: models, adapters, data, libraries."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"type": c["type"], "name": c["name"],
             "version": c["version"],
             "hashes": [{"alg": "SHA-256", "content": c["sha256"]}],
             "licenses": [{"license": {"id": c["license"]}}]}
            for c in components
        ],
    }


def licence_findings(bom: dict, commercial: bool) -> list[str]:
    out = []
    for c in bom["components"]:
        lic = c["licenses"][0]["license"]["id"].lower()
        if commercial and any(b in lic for b in COMMERCIAL_BLOCKERS):
            out.append(f"{c['name']}: {lic} forbids commercial use")
    return out
