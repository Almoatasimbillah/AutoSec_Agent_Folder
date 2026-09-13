"""Evidence Vault (Doc 03, Doc 11 & Doc 22).

Stores immutable raw technical artifacts (HTTP requests, responses, screenshots, tool logs)
with cryptographic SHA-256 integrity verification.
"""

import hashlib
from pathlib import Path
from typing import Dict, Any, Union
from datetime import datetime

from ..models.entities import Evidence


class EvidenceVault:
    """Manages raw evidence files with integrity hashing."""

    def __init__(self, base_data_dir: str = "data/engagements"):
        self.base_data_dir = Path(base_data_dir)

    def _get_evidence_dir(self, engagement_id: str) -> Path:
        evidence_dir = self.base_data_dir / engagement_id / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        return evidence_dir

    def store_artifact(
        self,
        engagement_id: str,
        artifact_type: str,
        content: Union[str, bytes],
        file_extension: str = "txt",
        metadata: Dict[str, Any] = None
    ) -> Evidence:
        """Save an artifact, compute SHA-256, and return an Evidence model."""
        evidence_dir = self._get_evidence_dir(engagement_id)
        
        # Ensure byte format for hashing
        byte_data = content.encode("utf-8") if isinstance(content, str) else content
        sha256_hash = hashlib.sha256(byte_data).hexdigest()

        # Filename based on hash
        clean_ext = file_extension.lstrip(".")
        filename = f"{sha256_hash[:16]}_{int(datetime.utcnow().timestamp())}.{clean_ext}"
        file_path = evidence_dir / filename

        # Write file
        with open(file_path, "wb") as f:
            f.write(byte_data)

        # Create model
        evidence_record = Evidence(
            engagement_id=engagement_id,
            artifact_type=artifact_type,
            file_path=str(file_path.as_posix()),
            sha256_hash=sha256_hash,
            metadata_info=metadata or {}
        )
        return evidence_record

    def verify_integrity(self, file_path: str, expected_hash: str) -> bool:
        """Verify that an artifact file has not been altered or tampered with."""
        path = Path(file_path)
        if not path.exists():
            return False

        with open(path, "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()

        return current_hash.lower() == expected_hash.lower()
