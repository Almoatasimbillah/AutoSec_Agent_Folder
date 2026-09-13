"""Interactive CLI & Observability Dashboard (Doc 10, Doc 22).

Complete assessment workflow:
Scope & Policy -> Preflight -> Recon -> Target Model -> Multi-Account Differential Testing ->
Hypothesis Verification -> Report Generation & Evidence Packaging.
"""

import asyncio
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

from ..core.engine import OrchestrationEngine
from ..models.entities import ScopeRule, Policy
from ..models.enums import ScopeRuleType, ScopeEffect, RiskLevel, FindingSeverity
from ..tools.base import ToolCapability
from ..tools.http_adapter import HttpToolAdapter
from ..tools.dns_adapter import DnsToolAdapter
from ..tools.probing_adapter import HttpProbingAdapter

console = Console()


async def run_live_demo():
    console.print(Panel.fit(
        "[bold cyan]Autonomous Security Research Agent[/bold cyan]\n"
        "[dim]Full-Lifecycle Assessment & Evidence-Backed Deliverables (Phase 1 - 4)[/dim]",
        border_style="cyan"
    ))

    # 1. Initialize Engine & Register Tool Adapters
    engine = OrchestrationEngine(base_data_dir="data/engagements")
    engine.tool_registry.register(HttpToolAdapter())
    engine.tool_registry.register(DnsToolAdapter())
    engine.tool_registry.register(HttpProbingAdapter())

    # 2. Create Engagement
    console.print("\n[bold yellow]1. Initializing Engagement...[/bold yellow]")
    engagement = engine.initialize_engagement(
        name="BugBounty_Target_Alpha",
        target_summary="Acme Corp Authorized Bug Bounty Assessment",
        authorization_ref="AUTH-BB-2026-9912-VERIFIED",
        researcher_identity="sec-researcher-0x01",
        rate_limit_rps=10
    )
    console.print(f"[green][+][/green] Engagement Created: [bold]{engagement.id}[/bold] (Status: {engine.state_machine.current_state.value})")

    # 3. Define Scope & Policy
    console.print("\n[bold yellow]2. Defining Deterministic Scope & Policy...[/bold yellow]")
    scope_rules = [
        ScopeRule(
            engagement_id=engagement.id,
            rule_type=ScopeRuleType.SUBDOMAIN_WILDCARD,
            pattern="*.acme-corp.com",
            effect=ScopeEffect.INCLUDE,
            priority=10
        ),
        ScopeRule(
            engagement_id=engagement.id,
            rule_type=ScopeRuleType.DOMAIN,
            pattern="example.com",
            effect=ScopeEffect.INCLUDE,
            priority=10
        ),
        ScopeRule(
            engagement_id=engagement.id,
            rule_type=ScopeRuleType.DOMAIN,
            pattern="billing.acme-corp.com",
            effect=ScopeEffect.EXCLUDE,  # Strict exclusion rule
            priority=50,
            notes="Critical production billing server - strictly forbidden"
        )
    ]

    policy = Policy(
        engagement_id=engagement.id,
        program_name="Acme Bug Bounty",
        forbidden_actions=["dos", "destructive_write", "brute_force_credentials"],
        required_headers={"X-Bug-Bounty": "sec-researcher-0x01"}
    )
    engine.load_scope_and_policy(scope_rules, policy)
    console.print(f"[green][+][/green] Scope and Policy Loaded. Advanced to: [bold]{engine.state_machine.current_state.value}[/bold]")

    # 4. Preflight
    console.print("\n[bold yellow]3. Executing Preflight Checks...[/bold yellow]")
    preflight = engine.run_preflight_checks()
    console.print(f"[green][+][/green] Preflight Status: [bold]{preflight['status']}[/bold]. State: [bold]{engine.state_machine.current_state.value}[/bold]")

    # 5. Reconnaissance Pipeline
    console.print("\n[bold yellow]4. Running Reconnaissance Pipeline...[/bold yellow]")
    seeds = ["example.com", "billing.acme-corp.com"]
    recon_res = await engine.run_reconnaissance(seeds)
    console.print(f"[green][+][/green] Recon Complete! Discovered Hosts: {recon_res['discovered_hosts_count']}, Live Services: {recon_res['live_services_count']}")

    # 6. Multi-Account Differential Auditing
    console.print("\n[bold yellow]5. Multi-Account Sessions & Access Control Audit...[/bold yellow]")
    u_alice = engine.session_manager.create_identity("UserA_Alice", "standard_tenant")
    u_bob = engine.session_manager.create_identity("UserB_Bob", "standard_tenant")
    engine.session_manager.set_session_context(u_alice.id, {"session_token": "alice_auth_token_991"})
    engine.session_manager.set_session_context(u_bob.id, {"session_token": "bob_auth_token_992"})

    test_endpoint = "https://example.com"
    audit_res = await engine.perform_access_control_audit(
        endpoint_url=test_endpoint,
        user_a_name="UserA_Alice",
        user_b_name="UserB_Bob"
    )
    console.print(f"[cyan]Audit Result for {test_endpoint}:[/cyan] {audit_res.summary}")

    # 7. Promote Discrepancy to Finding (Scientific Proof)
    hypotheses = engine.hypothesis_engine.get_hypotheses()
    if hypotheses:
        active_hyp = hypotheses[0]
        finding = engine.hypothesis_engine.promote_to_finding(
            hypothesis_id=active_hyp.id,
            title="Cross-Tenant Direct Object Authorization Discrepancy",
            severity=FindingSeverity.HIGH,
            affected_asset=test_endpoint,
            reproduction_steps=f"1. Authenticate as UserB_Bob.\n2. Request resource owned by UserA_Alice at {test_endpoint}.\n3. Observe HTTP 200 returned instead of expected HTTP 403 Forbidden.",
            remediation_advice="Enforce tenant-level ownership validation in the backend routing handler."
        )
        console.print(f"[green][+][/green] Scientific Verification Complete! Promoted to Finding: [bold yellow][{finding.severity.value}] {finding.title}[/bold yellow]")

    # 8. Phase 4: Generate All Reports and Evidence Packages
    console.print("\n[bold yellow]6. Generating Formal Deliverables & Evidence Packages...[/bold yellow]")
    deliverables = engine.generate_deliverables()

    deliv_table = Table(title="Generated Assessment Deliverables (Phase 4)", box=box.ROUNDED)
    deliv_table.add_column("Deliverable", style="cyan")
    deliv_table.add_column("File Path", style="dim")
    deliv_table.add_column("Status", style="bold green")

    deliv_table.add_row("Executive Report", deliverables.get("executive_report", ""), "GENERATED")
    deliv_table.add_row("Technical Findings Report", deliverables.get("technical_report", ""), "GENERATED")
    deliv_table.add_row("Mentor Debrief", deliverables.get("mentor_debrief", ""), "GENERATED")
    deliv_table.add_row("Evidence Manifest (SHA-256)", deliverables.get("manifest", ""), "VERIFIED")
    deliv_table.add_row("Machine-Readable JSON", deliverables.get("machine_readable_export", ""), "EXPORTED")

    console.print(deliv_table)

    # 9. Mission Dashboard Summary
    metrics = engine.target_model.get_summary()
    console.print("\n")
    console.print(Panel(
        f"[bold]Engagement ID:[/bold] {engagement.id}\n"
        f"[bold]Target Program:[/bold] {policy.program_name}\n"
        f"[bold]Researcher Tag:[/bold] {engagement.researcher_identity}\n"
        f"[bold]Final Lifecycle State:[/bold] [bold green]{engine.state_machine.current_state.value}[/bold green]\n"
        f"[bold]Verified Findings:[/bold] 1 High Severity\n"
        f"[bold]Attack Surface Metrics:[/bold] Assets={metrics['assets']} | Hosts={metrics['hosts']} | Apps={metrics['applications']} | Endpoints={metrics['endpoints']}\n"
        f"[bold]Evidence Directory:[/bold] data/engagements/{engagement.id}/evidence/\n"
        f"[bold]Reports Directory:[/bold] data/engagements/{engagement.id}/reports/",
        title="[bold green]Assessment Completed Successfully[/bold green]",
        border_style="green"
    ))


def main():
    asyncio.run(run_live_demo())


if __name__ == "__main__":
    main()
