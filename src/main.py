from __future__ import annotations
import argparse
import csv
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .loader import load_yaml_documents
from .model import BindingObj, RoleObj, RoleRef, Subject, Rule
from .graph_build import build_graph
from .path_finder import find_findings, highest_findings_by_subject
from .report import to_json, write_json, write_md
from .normalize import norm_role_obj

SUPPORTED_RBAC_KINDS = {
    "serviceaccount", "role", "clusterrole", "rolebinding", "clusterrolebinding"
}

def parse_objects(docs: List[Dict[str, Any]]) -> Tuple[List[RoleObj], List[BindingObj]]:
    roles: List[RoleObj] = []
    bindings: List[BindingObj] = []

    for doc in docs:
        kind = (doc.get("kind") or "").strip()
        k = kind.lower()
        meta = doc.get("metadata", {}) or {}
        name = meta.get("name")
        namespace = meta.get("namespace")
        if not kind or not name:
            continue

        if k == "role" or k == "clusterrole":
            rules = []
            for r in (doc.get("rules") or []):
                if isinstance(r, dict):
                    rules.append(Rule.from_dict(r))
            roles.append(RoleObj(kind=kind, name=name, namespace=namespace, rules=rules))

        elif k == "rolebinding" or k == "clusterrolebinding":
            subj_list: List[Subject] = []
            for s in (doc.get("subjects") or []):
                if not isinstance(s, dict):
                    continue
                subj_list.append(Subject(
                    kind=s.get("kind", ""),
                    name=s.get("name", ""),
                    namespace=s.get("namespace"),
                ))
            rr = doc.get("roleRef") or {}
            role_ref = None
            if isinstance(rr, dict) and rr.get("kind") and rr.get("name"):
                role_ref = RoleRef(kind=rr.get("kind"), name=rr.get("name"), apiGroup=rr.get("apiGroup", "rbac.authorization.k8s.io"))
            bindings.append(BindingObj(kind=kind, name=name, namespace=namespace, subjects=subj_list, roleRef=role_ref))

        # ignore other kinds

    return roles, bindings

def analyze(paths: List[str], out_prefix: str) -> Dict[str, Any]:
    docs = load_yaml_documents(paths)
    roles, bindings = parse_objects(docs)
    g = build_graph(roles, bindings)
    findings = find_findings(g)
    # Keep highest severity per subject to reduce noise (still explainable)
    findings = highest_findings_by_subject(findings)

    payload = to_json(findings, metadata={"inputs": paths, "role_count": len(roles), "binding_count": len(bindings), "node_count": g.number_of_nodes(), "edge_count": g.number_of_edges()})
    write_json(out_prefix + ".json", payload)
    write_md(out_prefix + ".md", payload)
    return payload

def batch(scenarios_dir: str, out_dir: str) -> None:
    scenarios = []
    base = Path(scenarios_dir)
    outp = Path(out_dir)
    outp.mkdir(parents=True, exist_ok=True)

    summary_rows = []
    for scenario_path in sorted([p for p in base.iterdir() if p.is_dir()]):
        manifest = scenario_path / "manifests.yaml"
        if not manifest.exists():
            continue
        expected_path = scenario_path / "expected.json"
        expected = {}
        if expected_path.exists():
            import json
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
        out_prefix = str(outp / scenario_path.name)
        payload = analyze([str(manifest)], out_prefix)
        detected = payload["meta"]["overall_severity"]
        exp = expected.get("overall_severity", "")
        summary_rows.append({
            "scenario": scenario_path.name,
            "expected_overall_severity": exp,
            "detected_overall_severity": detected,
            "correct": (exp == detected) if exp else "",
            "finding_count": payload["meta"]["finding_count"],
        })

    # write summary.csv
    summary_csv = outp / "summary.csv"
    with open(summary_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["scenario","expected_overall_severity","detected_overall_severity","correct","finding_count"])
        writer.writeheader()
        writer.writerows(summary_rows)

def main():
    parser = argparse.ArgumentParser(prog="rbac-graph-detector", description="Static analysis of Kubernetes RBAC YAML to detect risky permissions and explainable paths.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_an = sub.add_parser("analyze", help="Analyze one or more YAML files.")
    p_an.add_argument("yamls", nargs="+", help="Paths to YAML manifest files (multi-doc supported).")
    p_an.add_argument("--out", required=True, help="Output prefix (without extension).")

    p_b = sub.add_parser("batch", help="Analyze scenario folders (each containing manifests.yaml).")
    p_b.add_argument("scenarios_dir", help="Directory containing scenario subfolders.")
    p_b.add_argument("--out", required=True, help="Output directory (results).")

    args = parser.parse_args()

    if args.cmd == "analyze":
        analyze(args.yamls, args.out)
        print(f"Wrote {args.out}.json and {args.out}.md")
    elif args.cmd == "batch":
        batch(args.scenarios_dir, args.out)
        print(f"Wrote summary.csv to {args.out}")

if __name__ == "__main__":
    main()
