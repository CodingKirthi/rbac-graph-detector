from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

@dataclass(frozen=True)
class Rule:
    apiGroups: Tuple[str, ...] = ("",)
    resources: Tuple[str, ...] = ()
    verbs: Tuple[str, ...] = ()
    resourceNames: Tuple[str, ...] = ()
    nonResourceURLs: Tuple[str, ...] = ()

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Rule":
        def tup(key: str) -> Tuple[str, ...]:
            v = d.get(key, [])
            if v is None:
                return tuple()
            if isinstance(v, str):
                return (v,)
            return tuple(v)
        return Rule(
            apiGroups=tup("apiGroups") or ("",),
            resources=tup("resources"),
            verbs=tup("verbs"),
            resourceNames=tup("resourceNames"),
            nonResourceURLs=tup("nonResourceURLs"),
        )

@dataclass(frozen=True)
class RoleRef:
    kind: str  # Role or ClusterRole
    name: str
    apiGroup: str = "rbac.authorization.k8s.io"

@dataclass(frozen=True)
class Subject:
    kind: str  # ServiceAccount, User, Group
    name: str
    namespace: Optional[str] = None

@dataclass
class RoleObj:
    kind: str  # Role or ClusterRole
    name: str
    namespace: Optional[str]
    rules: List[Rule] = field(default_factory=list)

@dataclass
class BindingObj:
    kind: str  # RoleBinding or ClusterRoleBinding
    name: str
    namespace: Optional[str]
    subjects: List[Subject] = field(default_factory=list)
    roleRef: Optional[RoleRef] = None
