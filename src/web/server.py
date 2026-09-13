"""FastAPI Web Server & Mission Control Dashboard Backend (Doc 10).

Provides REST APIs and serves the interactive Web Dashboard for managing target profiles,
dynamic scope rules, running reconnaissance, viewing attack surface graphs, and reading reports.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import os
import uvicorn
from fastapi import FastAPI, HTTPException, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from ..core.engine import OrchestrationEngine
from ..policy.profile_parser import ProfileParser
from ..policy.scope_manager import DynamicScopeManager
from ..models.enums import ScopeRuleType, ScopeEffect, AgentState, FindingSeverity
from ..tools.http_adapter import HttpToolAdapter
from ..tools.dns_adapter import DnsToolAdapter
from ..tools.probing_adapter import HttpProbingAdapter
from ..tools.repeater import InteractiveRepeater
from ..reporting.bugbounty import BugBountyReportGenerator
from ..core.copilot import SecurityCoPilot
from ..proxy.interceptor import PassiveInterceptionProxy


app = FastAPI(
    title="Autonomous Security Research Agent — Mission Control",
    description="Interactive Web Dashboard for Dynamic Scope, Rule Checklists, and Assessment Monitoring.",
    version="0.1.0"
)

STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

# Shared orchestrator instance
engine = OrchestrationEngine(base_data_dir="data/engagements")
engine.tool_registry.register(HttpToolAdapter())
engine.tool_registry.register(DnsToolAdapter())
engine.tool_registry.register(HttpProbingAdapter())

# Shared local passive proxy instance
proxy_instance = PassiveInterceptionProxy(
    scope_engine=engine.scope_engine,
    target_model=engine.target_model,
    host="127.0.0.1",
    port=8085
)


class ImportProfileRequest(BaseModel):
    yaml_content: str


class AddScopeRuleRequest(BaseModel):
    pattern: str
    rule_type: str = "DOMAIN"
    effect: str = "INCLUDE"
    priority: int = 10
    notes: Optional[str] = None


class QuickSetupScopeRequest(BaseModel):
    target_name: Optional[str] = "Security Assessment"
    primary_target: str
    target_type: str = "DOMAIN"
    additional_in_scope: List[str] = []
    out_of_scope: List[str] = []
    rate_limit_rps: int = 5
    researcher_identity: str = "almoatasem_bellah"


class RepeaterRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None


class CoPilotChatRequest(BaseModel):
    message: str


class ApplyScenarioRequest(BaseModel):
    scenario_id: str


class CustomScenarioRequest(BaseModel):
    title: str
    technologies: List[str]
    category: str = "Custom Research"
    hypothesis_statement: str
    summary: str
    reference: str = "User Contributed Writeup"
    severity: str = "MEDIUM"
    sample_path: str = "/"
    sample_method: str = "GET"
    sample_headers: Dict[str, str] = {}
    sample_body: Optional[str] = None


class RunCrawlerRequest(BaseModel):
    base_url: Optional[str] = None
    max_scripts: int = 15


class RunParamMinerRequest(BaseModel):
    endpoint_url: str


@app.get("/")
def get_index():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return JSONResponse({"message": "Web UI dashboard loading..."})
    return FileResponse(
        index_file,
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


def _apply_profile(parsed):
    eng = engine.initialize_engagement(
        name=parsed.engagement.name,
        target_summary=parsed.engagement.target_summary,
        authorization_ref=parsed.engagement.authorization_ref,
        researcher_identity=parsed.engagement.researcher_identity,
        rate_limit_rps=parsed.engagement.rate_limit_rps
    )
    engine.load_scope_and_policy(parsed.scope_rules, parsed.policy)
    preflight = engine.run_preflight_checks()
    return {
        "success": True,
        "engagement_id": eng.id,
        "preflight_status": preflight["status"],
        "lifecycle_state": engine.state_machine.current_state.value,
        "scope_rules_count": len(parsed.scope_rules),
        "rule_checkboxes": parsed.rule_checkboxes,
        "mandatory_headers": parsed.policy.required_headers
    }


@app.on_event("startup")
def startup_event():
    """Auto-load OWASP Juice Shop profile for Al-Moatasem Bellah on startup if available."""
    juice_profile = Path("config/juice_shop_profile.yaml")
    if juice_profile.exists() and not engine.current_engagement:
        try:
            with open(juice_profile, "r", encoding="utf-8") as f:
                content = f.read()
            parsed = ProfileParser.parse_yaml(content)
            _apply_profile(parsed)
            print("[MISSION CONTROL] Auto-initialized OWASP Juice Shop profile for Al-Moatasem Bellah.")
        except Exception as e:
            print(f"[MISSION CONTROL] Startup auto-load notice: {e}")


@app.post("/api/engagements/load-preset/{preset_name}")
def load_preset(preset_name: str):
    """Load a predefined profile preset ('juice_shop' or 'acme')."""
    if preset_name == "juice_shop":
        profile_path = Path("config/juice_shop_profile.yaml")
    elif preset_name == "acme":
        profile_path = Path("config/sample_target_profile.yaml")
    else:
        raise HTTPException(status_code=404, detail=f"Preset '{preset_name}' not recognized.")

    if not profile_path.exists():
        raise HTTPException(status_code=404, detail=f"Preset file not found: {profile_path}")

    with open(profile_path, "r", encoding="utf-8") as f:
        content = f.read()
    parsed = ProfileParser.parse_yaml(content)
    return _apply_profile(parsed)


@app.get("/api/health")
def health():
    return {"status": "ONLINE", "version": "0.1.0"}


@app.get("/api/engagements/current")
def get_current_engagement():
    if not engine.current_engagement:
        return {"active": False}
    
    metrics = engine.target_model.get_summary() if engine.target_model else {}
    policy = engine.policy_engine.policy
    
    return {
        "active": True,
        "id": engine.current_engagement.id,
        "name": engine.current_engagement.name,
        "target_summary": engine.current_engagement.target_summary,
        "researcher_identity": engine.current_engagement.researcher_identity,
        "status": engine.state_machine.current_state.value,
        "rate_limit_rps": engine.current_engagement.rate_limit_rps,
        "mandatory_headers": policy.required_headers if policy else {},
        "forbidden_actions": policy.forbidden_actions if policy else [],
        "metrics": metrics
    }


@app.post("/api/engagements/import")
def import_profile(req: ImportProfileRequest):
    """Import a YAML profile generated via ChatGPT template."""
    try:
        parsed = ProfileParser.parse_yaml(req.yaml_content)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=f"Failed to parse YAML: {str(ex)}")

    return _apply_profile(parsed)


@app.get("/api/scope")
def list_scope_rules():
    """List all current scope rules for active engagement."""
    if not engine.current_engagement:
        return {"rules": []}
    mgr = DynamicScopeManager(engine.db_manager, engine.scope_engine, engine.current_engagement.id)
    rules = mgr.list_rules()
    return {"rules": [r.model_dump() for r in rules]}


@app.post("/api/scope")
def add_scope_rule(req: AddScopeRuleRequest):
    """Dynamically add an In-Scope or Out-of-Scope rule at runtime."""
    if not engine.current_engagement:
        raise HTTPException(status_code=400, detail="No active engagement.")

    rtype = ScopeRuleType[req.rule_type.upper()] if req.rule_type.upper() in ScopeRuleType.__members__ else ScopeRuleType.DOMAIN
    reffect = ScopeEffect[req.effect.upper()] if req.effect.upper() in ScopeEffect.__members__ else ScopeEffect.INCLUDE
    prio = 50 if reffect == ScopeEffect.EXCLUDE else req.priority

    mgr = DynamicScopeManager(engine.db_manager, engine.scope_engine, engine.current_engagement.id)
    rule = mgr.add_rule(
        pattern=req.pattern,
        rule_type=rtype,
        effect=reffect,
        priority=prio,
        notes=req.notes
    )
    return {"success": True, "rule": rule.model_dump()}


@app.delete("/api/scope/{rule_id}")
def delete_scope_rule(rule_id: str):
    """Dynamically delete a scope rule."""
    if not engine.current_engagement:
        raise HTTPException(status_code=400, detail="No active engagement.")
    mgr = DynamicScopeManager(engine.db_manager, engine.scope_engine, engine.current_engagement.id)
    deleted = mgr.delete_rule(rule_id)
    return {"success": deleted}


@app.post("/api/scope/quick-setup")
def quick_setup_scope(req: QuickSetupScopeRequest):
    """Set up or update scope targets and policies directly without YAML."""
    clean_target = req.primary_target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    if not clean_target:
        raise HTTPException(status_code=400, detail="Primary target pattern cannot be empty.")

    eng = engine.initialize_engagement(
        name=req.target_name or f"Assessment of {clean_target}",
        target_summary=f"Authorized security assessment of {clean_target}",
        authorization_ref="AUTH-DIRECT-SETUP-2026",
        researcher_identity=req.researcher_identity or "almoatasem_bellah",
        rate_limit_rps=req.rate_limit_rps or 5
    )

    if not engine.policy_engine.policy:
        from ..models.entities import Policy
        engine.policy_engine.set_policy(Policy(
            engagement_id=eng.id,
            program_name=req.target_name or "Authorized Engagement",
            required_headers={
                "User-Agent": "AutonomousSecurityAuditor/1.0",
                "X-Security-Research": req.researcher_identity or "almoatasem_bellah"
            }
        ))
    else:
        engine.policy_engine.policy.required_headers["User-Agent"] = "AutonomousSecurityAuditor/1.0"
        engine.policy_engine.policy.required_headers["X-Security-Research"] = req.researcher_identity or "almoatasem_bellah"

    mgr = DynamicScopeManager(engine.db_manager, engine.scope_engine, eng.id)

    # Primary target
    primary_type = ScopeRuleType.SUBDOMAIN_WILDCARD if clean_target.startswith("*.") else ScopeRuleType.DOMAIN
    mgr.add_rule(pattern=clean_target, rule_type=primary_type, effect=ScopeEffect.INCLUDE, priority=10, notes="Primary Target")

    # Additional in-scope
    for item in req.additional_in_scope:
        c = item.strip().replace("https://", "").replace("http://", "").split("/")[0]
        if c:
            itype = ScopeRuleType.SUBDOMAIN_WILDCARD if c.startswith("*.") else ScopeRuleType.DOMAIN
            mgr.add_rule(pattern=c, rule_type=itype, effect=ScopeEffect.INCLUDE, priority=10, notes="Additional in-scope target")

    # Out-of-scope
    for item in req.out_of_scope:
        c = item.strip().replace("https://", "").replace("http://", "").split("/")[0]
        if c:
            itype = ScopeRuleType.SUBDOMAIN_WILDCARD if c.startswith("*.") else ScopeRuleType.DOMAIN
            mgr.add_rule(pattern=c, rule_type=itype, effect=ScopeEffect.EXCLUDE, priority=50, notes="Out-of-scope exclusion")

    # Advance lifecycle to RECON via preflight
    preflight = engine.run_preflight_checks()

    return {
        "success": True,
        "engagement_id": eng.id,
        "primary_target": clean_target,
        "rules_count": len(mgr.list_rules()),
        "lifecycle_state": engine.state_machine.current_state.value
    }


@app.post("/api/run-recon")
async def run_recon():
    """Trigger the reconnaissance pipeline on all active in-scope domains."""
    if not engine.current_engagement or not engine.recon_engine:
        raise HTTPException(status_code=400, detail="No active engagement.")

    mgr = DynamicScopeManager(engine.db_manager, engine.scope_engine, engine.current_engagement.id)
    in_scope_rules = [r.pattern for r in mgr.list_rules() if r.effect == ScopeEffect.INCLUDE]
    
    seeds = [r.lstrip("*.") for r in in_scope_rules if not r.startswith("http")]

    results = await engine.run_reconnaissance(seeds)
    return {
        "success": True,
        "results": results,
        "lifecycle_state": engine.state_machine.current_state.value
    }


@app.get("/api/attack-surface")
def get_attack_surface():
    """Retrieve the discovered attack surface tree."""
    if not engine.current_engagement or not engine.target_model:
        return {"summary": {}, "hierarchy": []}
    return {
        "summary": engine.target_model.get_summary(),
        "hierarchy": engine.target_model.get_hierarchy()
    }


@app.get("/api/hypotheses")
def get_hypotheses():
    """Retrieve active hypotheses."""
    if not engine.current_engagement or not engine.hypothesis_engine:
        return {"hypotheses": []}
    items = engine.hypothesis_engine.get_hypotheses()
    return {"hypotheses": [h.model_dump() for h in items]}


@app.post("/api/generate-reports")
def generate_reports():
    """Generate all assessment reports and export bundle."""
    if not engine.current_engagement or not engine.report_generator:
        raise HTTPException(status_code=400, detail="No active engagement.")
    
    deliverables = engine.generate_deliverables()
    return {
        "success": True,
        "lifecycle_state": engine.state_machine.current_state.value,
        "deliverables": deliverables
    }


@app.get("/api/findings")
def get_findings():
    """Retrieve all verified findings for active engagement."""
    if not engine.current_engagement or not engine.hypothesis_engine:
        return {"findings": []}
    items = engine.hypothesis_engine.get_findings()
    return {"findings": [f.model_dump() for f in items]}


@app.get("/api/timeline")
def get_timeline():
    """Retrieve chronological decision trail and execution steps for active engagement."""
    if not engine.current_engagement:
        return {"timeline": []}
    decisions = engine.get_decisions()
    return {"timeline": [d.model_dump() for d in decisions]}


@app.post("/api/run-assessment")
async def run_assessment():
    """Trigger the end-to-end security research & vulnerability assessment pipeline."""
    if not engine.current_engagement:
        raise HTTPException(status_code=400, detail="No active engagement.")

    mgr = DynamicScopeManager(engine.db_manager, engine.scope_engine, engine.current_engagement.id)
    in_scope_rules = [r.pattern for r in mgr.list_rules() if r.effect == ScopeEffect.INCLUDE]
    # Ensure state is ready for RECON
    if engine.state_machine.current_state == AgentState.POLICY_ANALYSIS:
        engine.run_preflight_checks()
    elif engine.state_machine.current_state in [AgentState.COMPLETED, AgentState.REPORTING]:
        engine.state_machine.transition_to(AgentState.RECON)

    seeds = [r.lstrip("*.") for r in in_scope_rules if not r.startswith("http")]
    results = await engine.run_full_security_assessment(seeds)
    return results


@app.get("/api/reports/{filename}")
def download_report(filename: str):
    """Download a generated report file (auto-generates if not yet produced)."""
    if not engine.current_engagement:
        raise HTTPException(status_code=400, detail="No active engagement.")
    
    file_path = Path("data/engagements") / engine.current_engagement.id / "reports" / filename
    if not file_path.exists():
        engine.generate_deliverables()
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found.")
    return FileResponse(file_path)


@app.post("/api/tools/repeater")
async def send_repeater_request(req: RepeaterRequest):
    """Execute a manual test request through the deterministic ActionGate."""
    if not engine.current_engagement or not engine.action_gate:
        raise HTTPException(status_code=400, detail="No active engagement.")

    repeater = InteractiveRepeater(action_gate=engine.action_gate)
    resp = await repeater.send_request(
        method=req.method,
        url=req.url,
        headers=req.headers,
        body=req.body
    )

    if resp.is_in_scope:
        engine._record_decision(
            action="repeater_manual_probe",
            rationale=f"Manual security test dispatched via Repeater: {req.method.upper()} {req.url}",
            expected="Inspect raw response status, headers, and body reflection.",
            actual=f"HTTP {resp.status_code} returned in {resp.latency_ms}ms"
        )

    return resp.model_dump()


@app.get("/api/findings/{finding_id}/bounty-report")
def get_bounty_report(finding_id: str):
    """Generate a ready-to-submit HackerOne/Bugcrowd report for a finding."""
    if not engine.current_engagement or not engine.hypothesis_engine:
        raise HTTPException(status_code=400, detail="No active engagement.")

    findings = engine.hypothesis_engine.get_findings()
    target_finding = next((f for f in findings if f.id == finding_id), None)
    if not target_finding:
        if finding_id.isdigit() and int(finding_id) < len(findings):
            target_finding = findings[int(finding_id)]
        else:
            raise HTTPException(status_code=404, detail="Finding not found.")

    markdown_report = BugBountyReportGenerator.generate_hackerone_markdown(
        finding=target_finding,
        researcher_identity=engine.current_engagement.researcher_identity,
        researcher_name="المعتصم بالله (Al-Moatasem Bellah)",
        program_name=engine.current_engagement.name
    )
    return {
        "finding_id": target_finding.id,
        "title": target_finding.title,
        "severity": target_finding.severity.value,
        "report_markdown": markdown_report
    }


@app.post("/api/copilot/chat")
def copilot_chat(req: CoPilotChatRequest):
    """AI Security Co-Pilot answering penetration testing and remediation queries."""
    copilot = SecurityCoPilot(engine_context=engine)
    result = copilot.generate_advice(req.message)
    return result.model_dump()


@app.get("/api/scenarios")
def get_scenarios():
    """Retrieve all writeup scenarios and target-matched playbooks."""
    all_scenarios = [s.model_dump() for s in engine.writeup_kb.get_all_scenarios()]
    
    # Calculate target-specific matches if engagement is active
    detected_tech = []
    endpoints = []
    if engine.target_model:
        try:
            detected_tech = [t.name for t in engine.target_model.get_technologies()]
            endpoints = [ep.path for ep in engine.target_model.get_endpoints()]
        except Exception:
            pass
            
    matches = engine.writeup_kb.find_applicable_scenarios(detected_tech, endpoints)
    matched_ids = [m["scenario"].id for m in matches]

    return {
        "total_scenarios": len(all_scenarios),
        "scenarios": all_scenarios,
        "matched_scenarios": [
            {
                "scenario": m["scenario"].model_dump(),
                "relevance_score": m["relevance_score"],
                "matched_tech": m["matched_tech"]
            }
            for m in matches
        ],
        "matched_ids": matched_ids,
        "detected_tech": detected_tech
    }


@app.post("/api/scenarios/apply")
def apply_scenario(req: ApplyScenarioRequest):
    """Deploy a scenario from the writeup knowledge base into the active hypothesis queue."""
    if not engine.current_engagement or not engine.hypothesis_engine:
        raise HTTPException(status_code=400, detail="No active engagement.")

    scen = engine.writeup_kb.get_scenario(req.scenario_id)
    if not scen:
        raise HTTPException(status_code=404, detail="Scenario not found.")

    primary_url = "https://target"
    if engine.target_model:
        apps = engine.target_model.get_applications()
        if apps:
            primary_url = apps[0].base_url

    hyp = engine.hypothesis_engine.create_hypothesis_from_scenario(
        scenario=scen,
        target_asset=primary_url,
        priority_score=8.0
    )

    engine._record_decision(
        action="manual_scenario_hypothesis_deployment",
        rationale=f"Operator deployed tactical writeup playbook: {scen.title} ({scen.reference})",
        expected="Prioritize hypothesis for non-destructive verification and reporting.",
        actual=f"Created candidate hypothesis {hyp.id} with priority 8.0"
    )

    return {
        "success": True,
        "hypothesis_id": hyp.id,
        "statement": hyp.statement,
        "scenario_id": scen.id
    }


@app.post("/api/scenarios/custom")
def add_custom_scenario(req: CustomScenarioRequest):
    """Import a custom writeup into the knowledge base."""
    sev = FindingSeverity.MEDIUM
    try:
        sev = FindingSeverity(req.severity.upper())
    except Exception:
        pass

    scenario = engine.writeup_kb.import_custom_writeup(
        title=req.title,
        technologies=req.technologies,
        category=req.category,
        hypothesis_statement=req.hypothesis_statement,
        summary=req.summary,
        reference=req.reference,
        severity=sev,
        sample_path=req.sample_path,
        sample_method=req.sample_method,
        sample_headers=req.sample_headers,
        sample_body=req.sample_body
    )

    return {
        "success": True,
        "scenario": scenario.model_dump()
    }


# =========================================================================
# PILLAR 1: SMART SPA CRAWLER & ROUTE MINER ENDPOINTS
# =========================================================================
@app.post("/api/crawler/run")
async def run_crawler_endpoint(req: RunCrawlerRequest):
    """Deep crawl active target for client-side SPA routes, REST endpoints, and forms."""
    if not engine.current_engagement:
        raise HTTPException(status_code=400, detail="No active engagement.")
    try:
        res = await engine.run_crawler(base_url=req.base_url, max_scripts=req.max_scripts)
        return res.model_dump()
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


# =========================================================================
# PILLAR 2: BUILT-IN PASSIVE INTERCEPTION PROXY ENDPOINTS
# =========================================================================
@app.post("/api/proxy/start")
async def start_proxy_endpoint():
    """Start local passive interception proxy on 127.0.0.1:8085."""
    try:
        proxy_instance.scope_engine = engine.scope_engine
        proxy_instance.target_model = engine.target_model
        await proxy_instance.start()
        return {
            "status": "RUNNING",
            "host": proxy_instance.host,
            "port": proxy_instance.port
        }
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@app.post("/api/proxy/stop")
async def stop_proxy_endpoint():
    """Stop the local passive interception proxy."""
    try:
        await proxy_instance.stop()
        return {"status": "STOPPED"}
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@app.get("/api/proxy/status")
def get_proxy_status():
    """Get current status of the passive proxy."""
    return {
        "is_running": proxy_instance.is_running,
        "host": proxy_instance.host,
        "port": proxy_instance.port,
        "captured_count": len(proxy_instance.traffic_history)
    }


@app.get("/api/proxy/traffic")
def get_proxy_traffic(limit: int = 100, in_scope_only: bool = False):
    """Retrieve recorded HTTP transactions from the passive proxy."""
    items = proxy_instance.get_traffic(limit=limit, in_scope_only=in_scope_only)
    return {
        "count": len(items),
        "traffic": [t.model_dump() for t in items]
    }


@app.delete("/api/proxy/traffic")
def clear_proxy_traffic():
    """Clear traffic history buffer."""
    proxy_instance.clear_traffic()
    return {"success": True}


# =========================================================================
# PILLAR 3: PARAMETER MINER & ANOMALY DETECTOR ENDPOINTS
# =========================================================================
@app.post("/api/audit/param-miner/run")
async def run_param_miner_endpoint(req: RunParamMinerRequest):
    """Probe endpoint for parameter responsiveness, status drift, and reflection context."""
    if not engine.current_engagement:
        raise HTTPException(status_code=400, detail="No active engagement.")
    try:
        results = await engine.run_parameter_mining(endpoint_url=req.endpoint_url)
        return {
            "endpoint_url": req.endpoint_url,
            "anomalies_count": len(results),
            "results": [r.model_dump() for r in results]
        }
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


# =========================================================================
# PILLAR 4: VULNERABILITY CHAINING & VISUAL ATTACK GRAPH ENDPOINTS
# =========================================================================
@app.get("/api/attack-graph")
def get_attack_graph_endpoint():
    """Retrieve current attack graph topology, node connections, and multi-step exploit chains."""
    try:
        graph = engine.get_attack_graph()
        return graph.model_dump()
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


def start_server(host: str = "127.0.0.1", port: int = 8000):
    """Run the web server."""
    uvicorn.run("src.web.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    start_server()
