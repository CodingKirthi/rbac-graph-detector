# RBAC Graph Detector (Kubernetes YAML Static Analysis)

This project parses Kubernetes RBAC YAML manifests, builds a relationship graph, and reports risky permissions and explainable evidence paths.

## Features
- Parse multi-document YAML
- Extract: ServiceAccount, Role, ClusterRole, RoleBinding, ClusterRoleBinding
- Build graph: Subject -> Binding -> Role -> Rules
- Detect risky permissions (cluster-admin, wildcards, RBAC takeover verbs, secrets read, pods/exec, etc.)
- Output JSON + Markdown reports per scenario + summary CSV

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python src/main.py analyze scenarios/s02_cluster_admin/manifests.yaml --out results/s02
python src/main.py batch scenarios --out results
```

## CLI
- `analyze <yaml...>`: analyze one or more YAML files
- `batch <scenarios_dir>`: analyze each scenario folder containing `manifests.yaml`

Outputs:
- `<out>.json`
- `<out>.md`
- `results/summary.csv` for batch mode

## Notes
This is static analysis of manifests (no live cluster access).
