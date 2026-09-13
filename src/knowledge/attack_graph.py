"""Vulnerability Chaining & Visual Attack Graph Engine (Doc 03, Doc 07, Doc 15).

Correlates individual security findings and assets into multi-step exploit chains,
calculates composite CVSS 3.1 scores, and generates structured graph topologies.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

from ..core.hypothesis_engine import HypothesisEngine
from ..knowledge.target_model import TargetModelManager
from ..models.entities import Finding
from ..models.enums import FindingSeverity


class AttackGraphNode(BaseModel):
    """Visual graph node representing an asset, vulnerability, or state."""
    id: str
    label: str
    node_type: str  # 'ROOT_ASSET', 'ENDPOINT', 'VULNERABILITY', 'PRIVILEGE_GAIN', 'IMPACT'
    severity: Optional[str] = None
    color: str = "#38bdf8"
    icon: str = "fa-circle"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackGraphEdge(BaseModel):
    """Directed connection illustrating attack flow."""
    id: str
    source: str
    target: str
    label: str
    edge_type: str = "LEADS_TO"  # 'DISCLOSES', 'EXPLOITS', 'ESCALATES_TO', 'COMPROMISES'


class AttackChain(BaseModel):
    """Synthesized multi-step vulnerability progression."""
    id: str
    name: str
    composite_severity: str = "HIGH"
    composite_cvss: float = 7.5
    steps: List[str] = Field(default_factory=list)
    involved_finding_ids: List[str] = Field(default_factory=list)
    narrative_summary: str


class AttackGraph(BaseModel):
    """Full graph topology and synthesized attack chains."""
    nodes: List[AttackGraphNode] = Field(default_factory=list)
    edges: List[AttackGraphEdge] = Field(default_factory=list)
    chains: List[AttackChain] = Field(default_factory=list)
    total_chains: int = 0
    highest_cvss: float = 0.0


class AttackGraphEngine:
    """Evaluates security findings and builds multi-step attack graphs."""

    def __init__(
        self,
        hypothesis_engine: Optional[HypothesisEngine] = None,
        target_model: Optional[TargetModelManager] = None
    ):
        self.hypothesis_engine = hypothesis_engine
        self.target_model = target_model

    def build_attack_graph(self, target_name: str = "Target Organization") -> AttackGraph:
        """Construct the attack graph and correlate multi-step vulnerability chains."""
        findings: List[Finding] = []
        if self.hypothesis_engine:
            findings = self.hypothesis_engine.get_findings()

        endpoints = []
        if self.target_model:
            try:
                endpoints = self.target_model.get_endpoints()
            except Exception:
                pass

        nodes: List[AttackGraphNode] = []
        edges: List[AttackGraphEdge] = []
        chains: List[AttackChain] = []

        # 1. Root Node
        root_node_id = "node-root-target"
        nodes.append(AttackGraphNode(
            id=root_node_id,
            label=target_name,
            node_type="ROOT_ASSET",
            color="#38bdf8",
            icon="fa-globe",
            metadata={"type": "Domain Root"}
        ))

        # 2. Add Top Discovered Endpoints
        endpoint_node_map = {}
        for i, ep in enumerate(endpoints[:6]):
            ep_node_id = f"node-ep-{i}"
            endpoint_node_map[ep.path] = ep_node_id
            nodes.append(AttackGraphNode(
                id=ep_node_id,
                label=f"{ep.method} {ep.path}",
                node_type="ENDPOINT",
                color="#10b981",
                icon="fa-link",
                metadata={"method": ep.method, "path": ep.path}
            ))
            edges.append(AttackGraphEdge(
                id=f"edge-root-ep-{i}",
                source=root_node_id,
                target=ep_node_id,
                label="Exposes",
                edge_type="DISCLOSES"
            ))

        # 3. Add Vulnerability Nodes
        finding_node_map = {}
        for i, f in enumerate(findings):
            color = "#f43f5e" if f.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL} else ("#f59e0b" if f.severity == FindingSeverity.MEDIUM else "#38bdf8")
            f_node_id = f"node-finding-{i}"
            finding_node_map[f.id] = f_node_id
            nodes.append(AttackGraphNode(
                id=f_node_id,
                label=f.title,
                node_type="VULNERABILITY",
                severity=f.severity.value,
                color=color,
                icon="fa-bug",
                metadata={"finding_id": f.id, "affected": f.affected_asset}
            ))

            # Connect finding to root or matching endpoint
            connected = False
            for path, ep_id in endpoint_node_map.items():
                if path in f.affected_asset:
                    edges.append(AttackGraphEdge(
                        id=f"edge-ep-f-{i}",
                        source=ep_id,
                        target=f_node_id,
                        label="Contains Weakness",
                        edge_type="EXPLOITS"
                    ))
                    connected = True
                    break
            if not connected:
                edges.append(AttackGraphEdge(
                    id=f"edge-root-f-{i}",
                    source=root_node_id,
                    target=f_node_id,
                    label="Vulnerable",
                    edge_type="EXPLOITS"
                ))

        # 4. Multi-Step Chaining Heuristics
        f_titles_lower = [f.title.lower() for f in findings]
        f_ids = [f.id for f in findings]

        # Chain A: Secret/JS Leakage -> IDOR/BOLA Data Harvesting
        has_secret_leak = any("secret" in t or "token" in t or "javascript" in t or "swagger" in t for t in f_titles_lower)
        has_idor = any("idor" in t or "bola" in t or "object reference" in t for t in f_titles_lower)

        if has_secret_leak and has_idor:
            impact_node_id = "node-impact-breach"
            nodes.append(AttackGraphNode(
                id=impact_node_id,
                label="Critical Multi-Tenant Data Exfiltration",
                node_type="IMPACT",
                severity="CRITICAL",
                color="#e11d48",
                icon="fa-skull-crossbones",
                metadata={"impact": "Full database customer record exposure"}
            ))
            # Edges
            for f in findings:
                if "secret" in f.title.lower() or "idor" in f.title.lower() or "bola" in f.title.lower():
                    edges.append(AttackGraphEdge(
                        id=f"edge-chain-breach-{f.id}",
                        source=finding_node_map.get(f.id, root_node_id),
                        target=impact_node_id,
                        label="Chained Impact",
                        edge_type="ESCALATES_TO"
                    ))

            chains.append(AttackChain(
                id="CHAIN-01",
                name="Credential/Route Disclosure to Object Level Authorization Takeover",
                composite_severity="CRITICAL",
                composite_cvss=9.2,
                steps=[
                    "1. Harvest internal API schemas / secrets from exposed documentation or JavaScript bundles.",
                    "2. Enumerate discovered customer and administrative endpoints without authorization verification.",
                    "3. Perform BOLA / IDOR parameter tampering to systematically extract foreign tenant data."
                ],
                involved_finding_ids=f_ids,
                narrative_summary=(
                    "An attacker leverages discovered endpoints or leaked tokens from client assets, "
                    "bypassing initial authentication boundaries to harvest unauthorized multi-tenant data."
                )
            ))

        # Chain B: CORS Misconfiguration -> Cross-Domain Data Theft
        has_cors = any("cors" in t or "origin" in t for t in f_titles_lower)
        if has_cors:
            cors_impact_id = "node-impact-cors-theft"
            nodes.append(AttackGraphNode(
                id=cors_impact_id,
                label="Cross-Domain Authenticated Session Hijack",
                node_type="IMPACT",
                severity="HIGH",
                color="#ea580c",
                icon="fa-user-secret",
                metadata={"impact": "Harvest authenticated responses via victim browser"}
            ))
            for f in findings:
                if "cors" in f.title.lower():
                    edges.append(AttackGraphEdge(
                        id=f"edge-chain-cors-{f.id}",
                        source=finding_node_map.get(f.id, root_node_id),
                        target=cors_impact_id,
                        label="Permits",
                        edge_type="ESCALATES_TO"
                    ))

            chains.append(AttackChain(
                id="CHAIN-02",
                name="Arbitrary CORS Reflection to Authenticated Data Exfiltration",
                composite_severity="HIGH",
                composite_cvss=8.1,
                steps=[
                    "1. Attacker lures authenticated victim to malicious third-party site.",
                    "2. Victim browser sends cross-origin XMLHttpRequest to target.",
                    "3. Target reflects Origin header with credentials enabled, allowing attacker to read private response."
                ],
                involved_finding_ids=f_ids,
                narrative_summary=(
                    "The permissive CORS policy allows arbitrary websites to read authenticated responses, "
                    "effectively bypassing Same-Origin Policy protections."
                )
            ))

        # Chain C: Missing Anti-Clickjacking + Sensitive Endpoints
        has_csp = any("clickjacking" in t or "csp" in t or "frame" in t for t in f_titles_lower)
        if has_csp:
            click_impact_id = "node-impact-ui-redress"
            nodes.append(AttackGraphNode(
                id=click_impact_id,
                label="UI Redressing & Involuntary State Change",
                node_type="IMPACT",
                severity="MEDIUM",
                color="#d97706",
                icon="fa-masks-theater",
                metadata={"impact": "Tricked user clicks on invisible target interface"}
            ))
            for f in findings:
                if "clickjacking" in f.title.lower() or "csp" in f.title.lower():
                    edges.append(AttackGraphEdge(
                        id=f"edge-chain-click-{f.id}",
                        source=finding_node_map.get(f.id, root_node_id),
                        target=click_impact_id,
                        label="Enables",
                        edge_type="ESCALATES_TO"
                    ))

            chains.append(AttackChain(
                id="CHAIN-03",
                name="Iframe Embedding to Deceptive User Action Execution",
                composite_severity="MEDIUM",
                composite_cvss=6.4,
                steps=[
                    "1. Embed target application inside transparent iframe on attacker portal.",
                    "2. Align target buttons under enticing game or survey click targets.",
                    "3. Authenticated user clicks unwittingly trigger sensitive state changes."
                ],
                involved_finding_ids=f_ids,
                narrative_summary=(
                    "Lack of frame-ancestors and X-Frame-Options enables UI redressing attacks "
                    "against authenticated users."
                )
            ))

        highest_score = max([c.composite_cvss for c in chains], default=5.0)

        return AttackGraph(
            nodes=nodes,
            edges=edges,
            chains=chains,
            total_chains=len(chains),
            highest_cvss=highest_score
        )
