import json
from src.loader import load_yaml_documents
from src.main import parse_objects

def test_parse_roles_and_bindings():
    docs = load_yaml_documents(["scenarios/s02_cluster_admin/manifests.yaml"])
    roles, bindings = parse_objects(docs)
    assert len(bindings) >= 1
