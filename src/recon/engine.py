"""Reconnaissance Orchestrator & Pipeline (Doc 17).

Executes staged discovery (Intake -> DNS -> Probing -> Tech Mapping -> Ingestion)
and tracks Discovery Saturation.
"""

from typing import List, Dict, Any, Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from ..knowledge.target_model import TargetModelManager

from ..policy.action_gate import ActionGate
from ..tools.registry import ToolRegistry
from ..tools.base import ToolCapability, ToolExecutionRequest
from ..models.enums import AssetType, RiskLevel
from .normalizer import AssetNormalizer


class ReconEngine:
    """Orchestrates passive & active reconnaissance within scope."""

    def __init__(
        self,
        engagement_id: str,
        target_model: Any,
        action_gate: ActionGate,
        tool_registry: ToolRegistry
    ):
        self.engagement_id = engagement_id
        self.target_model = target_model
        self.action_gate = action_gate
        self.tool_registry = tool_registry

    async def run_discovery_pipeline(self, seed_domains: List[str]) -> Dict[str, Any]:
        """Execute complete multi-stage recon on seed domains."""
        cleaned_seeds = [AssetNormalizer.normalize_domain(d) for d in seed_domains if d]
        cleaned_seeds = AssetNormalizer.deduplicate(cleaned_seeds)

        discovered_hosts: List[str] = []
        live_services: List[Dict[str, Any]] = []

        # 1. DNS Resolution Stage
        dns_adapters = self.tool_registry.find_adapters_by_capability(ToolCapability.DNS_DISCOVERY)
        dns_adapter = dns_adapters[0] if dns_adapters else None

        for domain in cleaned_seeds:
            # Check gate
            gate_res = self.action_gate.validate_action(
                target=domain,
                action_name="dns_enumeration",
                risk_level=RiskLevel.LOW
            )
            if not gate_res.passed:
                continue

            # Ingest domain asset
            asset = self.target_model.add_asset(
                asset_type=AssetType.DOMAIN,
                value=domain,
                source="recon_seed",
                in_scope=True
            )

            if dns_adapter:
                req = ToolExecutionRequest(
                    engagement_id=self.engagement_id,
                    target=domain,
                    capability=ToolCapability.DNS_DISCOVERY
                )
                res = await dns_adapter.execute(req)
                if res.success:
                    ips = [obs["ip"] for obs in res.observations if obs.get("type") == "dns_a"]
                    if ips:
                        self.target_model.add_host(asset_id=asset.id, hostname=domain, ip_addresses=ips)
                        discovered_hosts.append(domain)

        # 2. HTTP Probing & Technology Detection Stage
        probing_adapters = self.tool_registry.find_adapters_by_capability(ToolCapability.HTTP_PROBING)
        prober = probing_adapters[0] if probing_adapters else None

        targets_to_probe = discovered_hosts if discovered_hosts else cleaned_seeds

        for host in targets_to_probe:
            gate_res = self.action_gate.validate_action(
                target=f"https://{host}",
                action_name="http_service_probing",
                risk_level=RiskLevel.LOW
            )
            if not gate_res.passed:
                continue

            if prober:
                req = ToolExecutionRequest(
                    engagement_id=self.engagement_id,
                    target=host,
                    capability=ToolCapability.HTTP_PROBING
                )
                res = await prober.execute(req)
                if res.success:
                    for obs in res.observations:
                        if obs.get("is_live"):
                            url = obs["url"]
                            techs = obs.get("technologies", [])
                            # Add Application
                            app = self.target_model.add_application(
                                name=f"App_{host}",
                                base_url=url,
                                technologies=techs
                            )
                            # Add default endpoint
                            self.target_model.add_endpoint(
                                application_id=app.id,
                                method="GET",
                                path="/"
                            )
                            live_services.append({
                                "host": host,
                                "url": url,
                                "technologies": techs,
                                "status": obs.get("status_code")
                            })

        # Summary of saturation
        summary = self.target_model.get_summary()
        is_saturated = summary["applications"] > 0 or len(discovered_hosts) > 0

        return {
            "discovered_hosts_count": len(discovered_hosts),
            "live_services_count": len(live_services),
            "live_services": live_services,
            "attack_surface_summary": summary,
            "discovery_saturation_reached": is_saturated
        }
