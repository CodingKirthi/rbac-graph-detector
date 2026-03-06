import json
from src.main import analyze

def test_cluster_admin_is_critical(tmp_path):
    out = tmp_path / "r"
    payload = analyze(["scenarios/s02_cluster_admin/manifests.yaml"], str(out))
    assert payload["meta"]["overall_severity"] == "CRITICAL"
