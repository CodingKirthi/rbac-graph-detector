# RBAC Graph Detector Report

- Generated: 2026-03-06T21:13:15.595592Z
- Overall severity: **HIGH**
- Findings: 1

## 1. HIGH — HIGH RBAC exposure via pod-exec

**Subject:** `sa:dev:exec-sa`

**Reason:** Can exec into pods

**Evidence path:**
- `sa:dev:exec-sa`
- `rolebinding:dev:bind-exec`
- `role:dev:pod-exec`

**Matched rules (summarized):**
- pods_exec
