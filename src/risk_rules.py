from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from .model import Rule, RoleObj

RBAC_RESOURCES = {
    "roles", "rolebindings", "clusterroles", "clusterrolebindings",
}
SECRETS_RESOURCES = {"secrets"}
PODS_EXEC = {("pods", "exec"), ("pods/exec", "")}  # handle both styles

@dataclass(frozen=True)
class Finding:
    subject_id: str
    severity: str
    title: str
    reason: str
    evidence_path: List[str]
    matched_rules: List[Dict]

SEVERITY_ORDER = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b

def rule_has_wildcards(rule: Rule) -> bool:
    return ("*" in rule.verbs) and ("*" in rule.resources or "*" in rule.nonResourceURLs)

def rule_allows(rule: Rule, verbs: Tuple[str, ...], resources: Tuple[str, ...]) -> bool:
    v_ok = "*" in rule.verbs or any(v in rule.verbs for v in verbs)
    r_ok = "*" in rule.resources or any(r in rule.resources for r in resources)
    return v_ok and r_ok

def classify_role(role_name: str, rules: List[Rule]) -> Tuple[str, List[Dict], List[str]]:
    # returns (severity, matched_rules, reasons)
    severity = "SAFE"
    matched: List[Dict] = []
    reasons: List[str] = []

    # cluster-admin is a special name used by Kubernetes
    if role_name == "cluster-admin":
        return "CRITICAL", [{"match": "cluster-admin name"}], ["Bound to cluster-admin"]

    for r in rules:
        if rule_has_wildcards(r):
            severity = max_severity(severity, "CRITICAL")
            matched.append({"match": "wildcards", "rule": rule_to_dict(r)})
            reasons.append("Wildcard verbs and resources/nonResourceURLs")

        # RBAC takeover: can create/update/patch/delete or bind/escalate roles/bindings
        takeover_verbs = ("create", "update", "patch", "delete", "bind", "escalate")
        if rule_allows(r, takeover_verbs, tuple(RBAC_RESOURCES)):
            severity = max_severity(severity, "CRITICAL")
            matched.append({"match": "rbac_takeover", "rule": rule_to_dict(r)})
            reasons.append("Can modify RBAC resources (roles/bindings)")

        # secrets read
        if rule_allows(r, ("get", "list", "watch"), tuple(SECRETS_RESOURCES)):
            severity = max_severity(severity, "HIGH")
            matched.append({"match": "secrets_read", "rule": rule_to_dict(r)})
            reasons.append("Can read secrets")

        # pods/exec
        if ("pods/exec" in r.resources) and ("create" in r.verbs or "*" in r.verbs):
            severity = max_severity(severity, "HIGH")
            matched.append({"match": "pods_exec", "rule": rule_to_dict(r)})
            reasons.append("Can exec into pods")

        # nodes access can be sensitive
        if rule_allows(r, ("get", "list", "watch"), ("nodes",)):
            severity = max_severity(severity, "HIGH")
            matched.append({"match": "nodes_read", "rule": rule_to_dict(r)})
            reasons.append("Can read node info")

    # de-duplicate reasons
    reasons = list(dict.fromkeys(reasons))
    return severity, matched, reasons

def rule_to_dict(r: Rule) -> Dict:
    return {
        "apiGroups": list(r.apiGroups),
        "resources": list(r.resources),
        "verbs": list(r.verbs),
        "resourceNames": list(r.resourceNames),
        "nonResourceURLs": list(r.nonResourceURLs),
    }
