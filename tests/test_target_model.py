"""Unit tests for Target Model & Attack Surface Manager (Doc 03, Doc 15)."""

import tempfile
import pytest
from src.storage.database import DatabaseManager
from src.knowledge.target_model import TargetModelManager
from src.models.enums import AssetType


def test_target_model_graph_building():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_mgr = DatabaseManager(base_data_dir=tmp_dir)
        eng_id = "test_eng_graph"

        tm = TargetModelManager(db_mgr, eng_id)

        # 1. Add Asset
        asset = tm.add_asset(AssetType.DOMAIN, "api.target.com", source="recon")
        assert asset.id is not None
        assert asset.value == "api.target.com"

        # 2. Add Host
        host = tm.add_host(asset_id=asset.id, hostname="api.target.com", ip_addresses=["10.0.0.1"])
        assert host.hostname == "api.target.com"
        assert "10.0.0.1" in host.ip_addresses

        # 3. Add Service
        service = tm.add_service(host_id=host.id, port=443, protocol="tcp", service_name="https")
        assert service.port == 443

        # 4. Add Application & Endpoint
        app = tm.add_application(name="API Service", base_url="https://api.target.com", technologies=["Nginx", "Django"])
        assert "Django" in app.technologies

        endpoint = tm.add_endpoint(application_id=app.id, method="POST", path="/v1/users/login")
        assert endpoint.method == "POST"
        assert endpoint.path == "/v1/users/login"

        # 5. Check Summary
        summary = tm.get_summary()
        assert summary["assets"] == 1
        assert summary["hosts"] == 1
        assert summary["services"] == 1
        assert summary["applications"] == 1
        assert summary["endpoints"] == 1

        # 6. Check Hierarchy Tree
        tree = tm.get_hierarchy()
        assert len(tree) == 1
        assert tree[0]["hostname"] == "api.target.com"
        assert len(tree[0]["applications"]) == 1
        assert len(tree[0]["applications"][0]["endpoints"]) == 1

        # Release Windows SQLite lock
        db_mgr.dispose()
