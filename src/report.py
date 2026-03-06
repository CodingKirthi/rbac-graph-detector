from __future__ import annotations
from typing import Dict, List, Any
import json
from datetime import datetime
from .risk_rules import Finding, SEVERITY_ORDER

def to_json(findings: List[Finding], metadata: Dict[str, Any]) -> Dict[str, Any]:
    # overall severity = max
    overall = "SAFE"
    for f in findings:
        if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(overall, 0):
            overall = f.severity
    return {
        "meta": {
            **metadata,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "overall_severity": overall,
            "finding_count": len(findings),
        },
        "findings": [
            {
                "subject_id": f.subject_id,
                "severity": f.severity,
                "title": f.title,
                "reason": f.reason,
                "evidence_path": f.evidence_path,
                "matched_rules": f.matched_rules,
            } for f in findings
        ]
    }

def write_json(path: str, payload: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

def write_md(path: str, payload: Dict[str, Any]) -> None:
    meta = payload.get("meta", {})
    findings = payload.get("findings", [])
    lines: List[str] = []
    lines.append(f"# RBAC Graph Detector Report")
    lines.append("")
    lines.append(f"- Generated: {meta.get('generated_at')}")
    lines.append(f"- Overall severity: **{meta.get('overall_severity')}**")
    lines.append(f"- Findings: {meta.get('finding_count')}")
    lines.append("")
    if not findings:
        lines.append("No findings.")
    else:
        for i, f in enumerate(findings, 1):
            lines.append(f"## {i}. {f['severity']} — {f['title']}")
            lines.append("")
            lines.append(f"**Subject:** `{f['subject_id']}`")
            lines.append("")
            lines.append(f"**Reason:** {f['reason']}")
            lines.append("")
            lines.append("**Evidence path:**")
            for p in f["evidence_path"]:
                lines.append(f"- `{p}`")
            if f.get("matched_rules"):
                lines.append("")
                lines.append("**Matched rules (summarized):**")
                for mr in f["matched_rules"]:
                    lines.append(f"- {mr.get('match')}")
            lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
