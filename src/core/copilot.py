"""AI Security Co-Pilot Assistant (Doc 10, Doc 16).

Provides an interactive, context-aware cybersecurity advisor for penetration testers
and security researchers, analyzing engagement context, findings, and advising on
testing methodologies, 403 bypasses, and remediation.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel


class CoPilotMessage(BaseModel):
    role: str  # 'user' or 'assistant'
    content: str


class CoPilotQueryRequest(BaseModel):
    message: str
    conversation_history: List[CoPilotMessage] = []


class CoPilotResponse(BaseModel):
    reply: str
    suggested_actions: List[str] = []
    relevant_endpoints: List[str] = []


class SecurityCoPilot:
    """Context-aware cybersecurity advisor embedded into Mission Control."""

    def __init__(self, engine_context: Any):
        self.engine = engine_context

    def generate_advice(self, query: str) -> CoPilotResponse:
        """Analyze query against active engagement data and generate contextual tactical advice."""
        q_lower = query.lower()

        target_name = "Target"
        target_summary = ""
        findings_count = 0
        endpoints_count = 0
        findings_titles = []

        if self.engine and self.engine.current_engagement:
            target_name = self.engine.current_engagement.name
            target_summary = self.engine.current_engagement.target_summary
            if self.engine.hypothesis_engine:
                f_list = self.engine.hypothesis_engine.get_findings()
                findings_count = len(f_list)
                findings_titles = [f.title for f in f_list]
            if self.engine.target_model:
                summary = self.engine.target_model.get_summary()
                endpoints_count = summary.get("endpoints", 0)

        # Tactical rule-based reasoning engine
        reply = ""
        suggested_actions = []
        relevant_endpoints = []

        # 1. 403 Bypass Queries
        if "403" in q_lower or "bypass" in q_lower or "forbidden" in q_lower:
            reply = (
                f"### 🛡️ 403 Forbidden Bypass Strategies for {target_name}:\n\n"
                "When encountering 403 Forbidden on discovered routes (e.g. `/ftp`, `/admin`), test these non-destructive techniques in the **Request Repeater**:\n\n"
                "1. **Header Spoofing / IP Forwarding:**\n"
                "   - `X-Forwarded-For: 127.0.0.1`\n"
                "   - `X-Custom-IP-Authorization: 127.0.0.1`\n"
                "   - `X-Originating-IP: 127.0.0.1`\n\n"
                "2. **URL Normalization & Path Traversals:**\n"
                "   - `/path/..;/` or `/path/%2e/`\n"
                "   - `X-Original-URL: /admin` or `X-Rewrite-URL: /admin`\n\n"
                "3. **HTTP Verb Tampering:**\n"
                "   - Try changing `GET` to `POST`, `HEAD`, or `OPTIONS`.\n"
            )
            suggested_actions = ["Open /ftp in Repeater", "Add X-Forwarded-For header", "Run Differential Access Test"]
            relevant_endpoints = ["/ftp", "/admin", "/api/Challenges"]

        # 2. CSP / Clickjacking / Header Queries
        elif "csp" in q_lower or "content security policy" in q_lower or "x-frame" in q_lower or "clickjacking" in q_lower:
            reply = (
                f"### 🔍 Content Security Policy & Framing Analysis for {target_name}:\n\n"
                "The target lacks a restrictive **Content-Security-Policy (CSP)** and **X-Frame-Options** header:\n\n"
                "1. **Clickjacking Risk:** Without `X-Frame-Options: DENY` or `frame-ancestors 'none'`, the target can be rendered inside an `<iframe>` on an attacker's website, allowing UI redressing.\n"
                "2. **XSS Mitigation:** Without a CSP with strict `script-src` and `default-src`, any injection vulnerability can immediately execute third-party JavaScript without browser-level blocking.\n\n"
                "**Remediation Recommendation:**\n"
                "```http\n"
                "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\n"
                "X-Frame-Options: DENY\n"
                "```"
            )
            suggested_actions = ["Generate HackerOne Report for CSP", "Inspect iframe embedding PoC"]

        # 3. IDOR / BOLA Queries
        elif "idor" in q_lower or "bola" in q_lower or "authorization" in q_lower:
            reply = (
                f"### 🎯 IDOR & BOLA Assessment Tactics:\n\n"
                f"For {target_name}, several REST API routes manage object IDs (e.g. `/api/Users/1`, `/rest/basket/1`, `/api/Challenges/1`).\n\n"
                "**Testing Workflow:**\n"
                "1. Capture a request accessing your own entity ID in the **Request Repeater**.\n"
                "2. Increment the ID to another index (`1` -> `2`).\n"
                "3. Remove authentication cookies/headers and compare response status and body.\n"
                "4. If unauthenticated requests return full JSON data, promote the issue as a High/Critical BOLA finding.\n"
            )
            suggested_actions = ["Open /api/Users/1 in Repeater", "Compare Session A vs Anonymous", "View Findings"]
            relevant_endpoints = ["/api/Users/1", "/rest/basket/1", "/api/Challenges/1"]

        # 4. Summary / Status Queries
        elif "summary" in q_lower or "status" in q_lower or "findings" in q_lower or "help" in q_lower or "thgrah" in q_lower:
            f_bullets = "\n".join([f"- **{t}**" for t in findings_titles[:5]]) or "- No verified findings recorded yet."
            reply = (
                f"### 📊 Mission Control Status Brief for Al-Moatasem Bellah:\n\n"
                f"- **Target:** `{target_name}`\n"
                f"- **Summary:** {target_summary}\n"
                f"- **Verified Findings:** `{findings_count}`\n"
                f"- **Probed Endpoints:** `{endpoints_count}`\n\n"
                f"**Key Discovered Weaknesses:**\n{f_bullets}\n\n"
                "You can inspect any of these findings in the **Verified Findings** tab, reproduce them in the **Request Repeater**, or generate ready-to-submit **HackerOne reports**."
            )
            suggested_actions = ["Run Security Assessment", "View All Findings", "Open Request Repeater"]

        # 5. Default General Security Assistant Advice
        else:
            reply = (
                f"### 🛡️ Autonomous Security Assistant:\n\n"
                f"Analyzing query regarding **{target_name}**: *\"{query}\"*\n\n"
                f"The active engagement currently has **{findings_count} verified vulnerabilities** recorded across **{endpoints_count} mapped endpoints**.\n\n"
                "**Recommended Next Steps:**\n"
                "1. Use the **Request Repeater** to inspect and modify live HTTP requests with custom headers.\n"
                "2. Review the **Execution Steps & Audit Trail** to see the deterministic signals observed by the agent.\n"
                "3. Generate standardized **HackerOne Bug Bounty reports** directly from the findings view."
            )
            suggested_actions = ["Open Request Repeater", "Review Audit Trail", "Generate Deliverables"]

        return CoPilotResponse(
            reply=reply,
            suggested_actions=suggested_actions,
            relevant_endpoints=relevant_endpoints
        )
