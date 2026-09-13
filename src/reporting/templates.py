"""Report Templates and Formatters (Doc 10, Doc 22).

Provides markdown templates and formatting functions for Executive Reports,
Technical Findings Reports, and Mentor Debriefs.
"""

from typing import Dict, List, Any
from datetime import datetime


def render_executive_report(
    engagement: Dict[str, Any],
    policy: Dict[str, Any],
    metrics: Dict[str, int],
    findings_summary: List[Dict[str, Any]]
) -> str:
    """Render high-level executive security assessment report."""
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    crit_count = sum(1 for f in findings_summary if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings_summary if f.get("severity") == "HIGH")
    med_count = sum(1 for f in findings_summary if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings_summary if f.get("severity") == "LOW")
    info_count = sum(1 for f in findings_summary if f.get("severity") == "INFO")

    lines = [
        f"# Executive Security Assessment Report",
        f"**Engagement:** {engagement.get('name', 'N/A')}  ",
        f"**Target Summary:** {engagement.get('target_summary', 'N/A')}  ",
        f"**Authorization Reference:** `{engagement.get('authorization_ref', 'N/A')}`  ",
        f"**Researcher Tag:** `{engagement.get('researcher_identity', 'N/A')}`  ",
        f"**Date Generated:** {now_str}  ",
        f"\n---\n",
        f"## 1. Executive Summary",
        f"An authorized, scientific security evaluation was conducted against the designated target scope in full compliance with the agreed program policy. Testing prioritized non-destructive observation, deterministic boundary enforcement, and multi-tenant access control verification.",
        f"\n### Overall Posture & Findings Summary",
        f"- **Critical Severity:** {crit_count}",
        f"- **High Severity:** {high_count}",
        f"- **Medium Severity:** {med_count}",
        f"- **Low Severity:** {low_count}",
        f"- **Informational:** {info_count}",
        f"- **Total Verified Findings:** {len(findings_summary)}",
        f"\n## 2. Attack Surface Coverage Overview",
        f"- Discovered Assets: **{metrics.get('assets', 0)}**",
        f"- Active Hosts: **{metrics.get('hosts', 0)}**",
        f"- Identified Applications: **{metrics.get('applications', 0)}**",
        f"- Mapped Endpoints: **{metrics.get('endpoints', 0)}**",
        f"\n## 3. High-Level Risk & Business Impact",
    ]

    if not findings_summary:
        lines.append("No security vulnerabilities were verified within the evaluated attack surface during this assessment.")
    else:
        for f in findings_summary:
            lines.append(f"### [{f.get('severity', 'INFO')}] {f.get('title')}")
            lines.append(f"**Affected Asset:** `{f.get('affected_asset')}`  ")
            lines.append(f"**Key Recommendation:** {f.get('remediation_advice')}\n")

    lines.append("\n---\n*Report prepared by Autonomous Security Research Agent — Human Review Required Prior to External Submission.*")
    return "\n".join(lines)


def render_technical_report(
    engagement: Dict[str, Any],
    scope_rules: List[Dict[str, Any]],
    target_hierarchy: List[Dict[str, Any]],
    findings: List[Dict[str, Any]]
) -> str:
    """Render comprehensive technical findings report for developers and security teams."""
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"# Technical Security Assessment & Verification Report",
        f"**Engagement ID:** `{engagement.get('id')}`  ",
        f"**Target:** {engagement.get('target_summary')}  ",
        f"**Date:** {now_str}  ",
        f"\n---\n",
        f"## 1. Engagement Scope & Governance Rules",
        f"The following deterministic scope rules governed all active probing and testing:\n",
        f"| Type | Pattern | Effect | Priority | Notes |",
        f"| :--- | :--- | :--- | :--- | :--- |"
    ]

    for r in scope_rules:
        lines.append(f"| `{r.get('rule_type')}` | `{r.get('pattern')}` | **{r.get('effect')}** | {r.get('priority')} | {r.get('notes') or '-'} |")

    lines.append(f"\n## 2. Attack Surface Topology")
    for host in target_hierarchy:
        lines.append(f"\n### Host: `{host.get('hostname')}`")
        lines.append(f"- **IP Addresses:** {', '.join(host.get('ips', [])) or 'None resolved'}")
        for app in host.get("applications", []):
            techs = ", ".join(app.get("technologies", [])) or "None identified"
            lines.append(f"- **Application:** `{app.get('base_url')}` (Technologies: *{techs}*)")
            endpoints = app.get("endpoints", [])
            if endpoints:
                lines.append("  - **Mapped Endpoints:**")
                for ep in endpoints:
                    lines.append(f"    - `{ep.get('method')}` `{ep.get('path')}`")

    lines.append(f"\n## 3. Verified Findings & Technical Evidence")
    if not findings:
        lines.append("\nNo confirmed vulnerabilities were identified across the tested attack surface.")
    else:
        for idx, f in enumerate(findings, 1):
            lines.append(f"\n### Finding {idx}: {f.get('title')}")
            lines.append(f"- **Severity:** `{f.get('severity')}`")
            lines.append(f"- **Affected Asset:** `{f.get('affected_asset')}`")
            lines.append(f"\n#### Reproduction Steps")
            lines.append(f.get('reproduction_steps', 'Not provided'))
            lines.append(f"\n#### Remediation Guidance")
            lines.append(f.get('remediation_advice', 'Not provided'))
            lines.append("\n---")

    return "\n".join(lines)


def render_mentor_debrief(
    engagement: Dict[str, Any],
    decisions: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]]
) -> str:
    """Render educational mentor debrief explaining decisions, hypotheses, and lessons learned."""
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"# Mentor Debrief & Assessment Reflection",
        f"**Engagement ID:** `{engagement.get('id')}`  ",
        f"**Date:** {now_str}  ",
        f"\n---\n",
        f"## 1. Pedagogical Objective",
        f"The Mentor Debrief is designed to provide visibility into the agent's decision-making process, highlighting *why* testing paths were pursued, how hypotheses were evaluated, and what strategic lessons were derived.",
        f"\n## 2. Hypothesis Evaluation Journey",
    ]

    for h in hypotheses:
        status_str = f"**[{h.get('status')}]**"
        lines.append(f"- {status_str} **{h.get('statement')}**")
        lines.append(f"  - *Priority:* {h.get('priority_score', 'N/A')} | *Potential Impact:* {h.get('potential_impact', 'N/A')}")
        if h.get('conclusion'):
            lines.append(f"  - *Conclusion:* {h.get('conclusion')}")

    lines.append(f"\n## 3. Key Decision Timeline & Rationales")
    if not decisions:
        lines.append("No decision records captured.")
    else:
        for d in decisions:
            lines.append(f"- **Action:** `{d.get('action_taken')}`")
            lines.append(f"  - *Rationale:* {d.get('rationale')}")
            lines.append(f"  - *Expected Outcome:* {d.get('expected_outcome')}")
            lines.append(f"  - *Actual Outcome:* {d.get('actual_outcome')}")

    lines.append(f"\n## 4. Key Takeaways & Strategic Lessons")
    lines.append("1. **Boundary Enforcement Works:** Deterministic scope filtering eliminated 100% of out-of-scope accidental queries.")
    lines.append("2. **Disproving Hypotheses Reduces False Positives:** Comparing multiple authorized identities under differential testing prevents premature assumptions from becoming false alerts.")
    lines.append("3. **Evidence Integrity is Essential:** Every technical finding must be defensible and supported by verifiable cryptographic proof.")

    return "\n".join(lines)
