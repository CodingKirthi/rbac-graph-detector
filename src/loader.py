from __future__ import annotations
from typing import Any, Dict, Iterable, List, Tuple
import yaml

def load_yaml_documents(paths: List[str]) -> List[Dict[str, Any]]:
    docs: List[Dict[str, Any]] = []
    for p in paths:
        with open(p, "r", encoding="utf-8") as f:
            content = f.read()
        for d in yaml.safe_load_all(content):
            if d is None:
                continue
            if not isinstance(d, dict):
                continue
            docs.append(d)
    return docs

def k8s_meta(doc: Dict[str, Any]) -> Tuple[str, str, str]:
    kind = doc.get("kind", "") or ""
    api = doc.get("apiVersion", "") or ""
    meta = doc.get("metadata", {}) or {}
    name = meta.get("name", "") or ""
    return kind, api, name
