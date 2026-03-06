from __future__ import annotations
from typing import Optional, Tuple
from .model import Subject, RoleRef, RoleObj

def norm_subject(s: Subject, default_ns: Optional[str]) -> str:
    kind = (s.kind or "").lower()
    if kind == "serviceaccount":
        ns = s.namespace or default_ns or "default"
        return f"sa:{ns}:{s.name}"
    if kind == "user":
        return f"user:{s.name}"
    if kind == "group":
        return f"group:{s.name}"
    # fallback
    ns = s.namespace or default_ns
    return f"{kind}:{ns+':' if ns else ''}{s.name}"

def norm_role_ref(rr: RoleRef, default_ns: Optional[str]) -> str:
    k = (rr.kind or "").lower()
    if k == "role":
        ns = default_ns or "default"
        return f"role:{ns}:{rr.name}"
    return f"clusterrole::{rr.name}"

def norm_role_obj(r: RoleObj) -> str:
    k = (r.kind or "").lower()
    if k == "role":
        ns = r.namespace or "default"
        return f"role:{ns}:{r.name}"
    return f"clusterrole::{r.name}"
