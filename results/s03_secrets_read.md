# RBAC Graph Detector Report

- Generated: 2026-03-06T21:13:15.593073Z
- Overall severity: **HIGH**
- Findings: 1

## 1. HIGH — HIGH RBAC exposure via read-secrets

**Subject:** `sa:dev:secret-reader`

**Reason:** Can read secrets

**Evidence path:**
- `sa:dev:secret-reader`
- `rolebinding:dev:bind-secrets`
- `role:dev:read-secrets`

**Matched rules (summarized):**
- secrets_read
