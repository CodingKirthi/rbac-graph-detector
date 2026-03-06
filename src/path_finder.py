from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional, Set

import networkx as nx

from .risk_rules import classify_role, Finding
from .model import Rule


def reconstruct_path(parent: Dict[str, Optional[str]], target: str) -> List[str]:
    path: List[str] = []
    cur: Optional[str] = target
    while cur is not None:
        path.append(cur)
        cur = parent.get(cur)
    path.reverse()
    return path


def bfs_from_subject(g: nx.DiGraph, start: str) -> Dict[str, Optional[str]]:
    """
    Standard BFS over outgoing edges from a subject node.
    Returns a parent map so we can reconstruct shortest paths.
    """
    queue = deque([start])
    visited: Set[str] = {start}
    parent: Dict[str, Optional[str]] = {start: None}

    while queue:
        current = queue.popleft()

        for neighbor in g.successors(current):
            if neighbor not in visited:
                visited.add(neighbor)
                parent[neighbor] = current
                queue.append(neighbor)

    return parent


def find_findings(g: nx.DiGraph) -> List[Finding]:
    findings: List[Finding] = []

    subject_nodes = [
        node_id
        for node_id, data in g.nodes(data=True)
        if data.get("type") == "subject"
    ]

    for sid in subject_nodes:
        parent = bfs_from_subject(g, sid)

        for reachable_node in parent.keys():
            node_data = g.nodes[reachable_node]
            if node_data.get("type") != "role":
                continue

            role_name = node_data.get("name") or reachable_node.split(":")[-1]
            rules: List[Rule] = node_data.get("rules") or []

            severity, matched_rules, reasons = classify_role(role_name, rules)

            if severity == "SAFE":
                continue

            evidence_path = reconstruct_path(parent, reachable_node)

            findings.append(
                Finding(
                    subject_id=sid,
                    severity=severity,
                    title=f"{severity} RBAC exposure via {role_name}",
                    reason="; ".join(reasons) if reasons else "Risky permissions",
                    evidence_path=evidence_path,
                    matched_rules=matched_rules,
                )
            )

    return findings


def highest_findings_by_subject(findings: List[Finding]) -> List[Finding]:
    order = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    best: Dict[str, int] = {}
    for f in findings:
        best[f.subject_id] = max(best.get(f.subject_id, 0), order.get(f.severity, 0))

    return [
        f for f in findings
        if order.get(f.severity, 0) == best.get(f.subject_id, 0)
    ]