from __future__ import annotations
from typing import Dict, List, Optional, Tuple
import networkx as nx

from .risk_rules import classify_role, Finding
from .model import Rule

def find_findings(g: nx.DiGraph) -> List[Finding]:
    findings: List[Finding] = []

    # Identify subjects
    subject_nodes = [n for n, d in g.nodes(data=True) if d.get("type") == "subject"]

    for sid in subject_nodes:
        # For each subject, follow subject -> binding -> role
        for bnode in g.successors(sid):
            if g.nodes[bnode].get("type") != "binding":
                continue
            for rnode in g.successors(bnode):
                if g.nodes[rnode].get("type") != "role":
                    continue
                role_name = g.nodes[rnode].get("name") or rnode.split(":")[-1]
                rules: List[Rule] = g.nodes[rnode].get("rules") or []
                severity, matched_rules, reasons = classify_role(role_name, rules)
                if severity != "SAFE":
                    findings.append(Finding(
                        subject_id=sid,
                        severity=severity,
                        title=f"{severity} RBAC exposure via {role_name}",
                        reason="; ".join(reasons) if reasons else "Risky permissions",
                        evidence_path=[sid, bnode, rnode],
                        matched_rules=matched_rules,
                    ))

    # Keep only highest severity per subject (but include ties)
    return findings

def highest_findings_by_subject(findings: List[Finding]) -> List[Finding]:
    order = {"SAFE":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    best: Dict[str, int] = {}
    for f in findings:
        best[f.subject_id] = max(best.get(f.subject_id, 0), order.get(f.severity, 0))
    return [f for f in findings if order.get(f.severity, 0) == best.get(f.subject_id, 0)]
