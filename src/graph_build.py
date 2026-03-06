from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import networkx as nx

from .model import BindingObj, RoleObj
from .normalize import norm_role_obj, norm_role_ref, norm_subject

def build_graph(roles: List[RoleObj], bindings: List[BindingObj]) -> nx.DiGraph:
    g = nx.DiGraph()

    # index roles
    role_index: Dict[str, RoleObj] = {norm_role_obj(r): r for r in roles}

    # add role nodes
    for rid, r in role_index.items():
        g.add_node(rid, type="role", kind=r.kind, name=r.name, namespace=r.namespace, rules=r.rules)

    # add binding + subject edges
    for b in bindings:
        bnode = binding_node_id(b)
        g.add_node(bnode, type="binding", kind=b.kind, name=b.name, namespace=b.namespace)

        if b.roleRef is not None:
            role_id = norm_role_ref(b.roleRef, b.namespace)
            # ensure role exists as node even if role object isn't present (external ref)
            if role_id not in g:
                g.add_node(role_id, type="role", kind=b.roleRef.kind, name=b.roleRef.name, namespace=(None if b.roleRef.kind.lower()=="clusterrole" else b.namespace), rules=[])
            g.add_edge(bnode, role_id, type="binds_to")

        for s in b.subjects:
            sid = norm_subject(s, b.namespace)
            if sid not in g:
                g.add_node(sid, type="subject", kind=s.kind, name=s.name, namespace=s.namespace or b.namespace)
            g.add_edge(sid, bnode, type="has_binding")
    return g

def binding_node_id(b: BindingObj) -> str:
    if (b.kind or "").lower() == "rolebinding":
        ns = b.namespace or "default"
        return f"rolebinding:{ns}:{b.name}"
    return f"clusterrolebinding::{b.name}"
