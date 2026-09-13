"""Unit tests for storage isolation and Evidence Vault integrity (Doc 03, Doc 11, Doc 22)."""

import tempfile
import pytest
from pathlib import Path
from src.storage.database import DatabaseManager
from src.storage.evidence_vault import EvidenceVault
from src.models.entities import Engagement


def test_engagement_database_isolation():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_mgr = DatabaseManager(base_data_dir=tmp_dir)

        eng1_id = "eng_alpha_001"
        eng2_id = "eng_beta_002"

        # Initialize engines
        eng1 = db_mgr.get_engine(eng1_id)
        eng2 = db_mgr.get_engine(eng2_id)

        # Confirm distinct physical SQLite database files
        db1_path = Path(tmp_dir) / eng1_id / "engagement.db"
        db2_path = Path(tmp_dir) / eng2_id / "engagement.db"

        assert db1_path.exists()
        assert db2_path.exists()
        assert db1_path != db2_path

        # Explicitly release SQLite file locks on Windows
        db_mgr.dispose()


def test_evidence_vault_sha256_integrity():
    with tempfile.TemporaryDirectory() as tmp_dir:
        vault = EvidenceVault(base_data_dir=tmp_dir)
        eng_id = "eng_test_evidence"
        content = "HTTP/1.1 200 OK\r\nServer: TestServer\r\n\r\nHello World"

        # Store artifact
        evidence = vault.store_artifact(
            engagement_id=eng_id,
            artifact_type="http_traffic",
            content=content,
            file_extension="txt"
        )

        assert Path(evidence.file_path).exists()
        assert len(evidence.sha256_hash) == 64

        # Verify integrity
        assert vault.verify_integrity(evidence.file_path, evidence.sha256_hash) is True

        # Tamper with file
        with open(evidence.file_path, "a") as f:
            f.write("TAMPERED")

        # Integrity should fail
        assert vault.verify_integrity(evidence.file_path, evidence.sha256_hash) is False
