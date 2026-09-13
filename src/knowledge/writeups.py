"""Real-World Bug Bounty Writeup & Scenario Knowledge Base (Doc 07, Doc 15, Doc 20).

Maintains a curated catalog of vulnerability scenarios inspired by disclosed
bug bounty reports (HackerOne, Bugcrowd, public post-mortems). Matches detected
technologies and endpoints to actionable security hypotheses.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

from ..models.enums import FindingSeverity


class SecurityScenario(BaseModel):
    """Structured security scenario derived from real-world bug bounty writeups."""
    id: str
    title: str
    reference: str  # e.g., 'HackerOne #328492', 'OWASP API #2'
    category: str   # 'API Security', 'CORS & Headers', 'OAuth & Auth', 'Info Disclosure', 'GraphQL'
    severity: FindingSeverity
    technologies: List[str]  # e.g., ['express', 'node', 'angular', 'rest']
    summary: str
    precondition: str
    hypothesis_statement: str
    recommended_remediation: str
    sample_path: str
    sample_method: str = "GET"
    sample_headers: Dict[str, str] = Field(default_factory=dict)
    sample_body: Optional[str] = None


class WriteupKnowledgeBase:
    """Curated security scenario library with automated tech-matching capabilities."""

    def __init__(self):
        self.scenarios: Dict[str, SecurityScenario] = {}
        self._load_seed_scenarios()

    def _load_seed_scenarios(self):
        seed_data = [
            SecurityScenario(
                id="SCENARIO-H1-CORS-01",
                title="CORS Misconfiguration with Arbitrary Origin Reflection",
                reference="HackerOne Disclosed #42616 & PortSwigger Research",
                category="CORS & Headers",
                severity=FindingSeverity.MEDIUM,
                technologies=["express", "node", "rest", "angular", "react", "fastapi"],
                summary="APIs that dynamically reflect the HTTP Origin request header with Access-Control-Allow-Credentials: true allow unauthorized cross-domain reads of sensitive data.",
                precondition="API responds to Origin: https://attacker.com with Access-Control-Allow-Origin: https://attacker.com and credentials allowed.",
                hypothesis_statement="The server reflects arbitrary origins in CORS response headers with credentials enabled, allowing authenticated data harvesting.",
                recommended_remediation="Implement a strict whitelist of trusted origins and avoid reflecting untrusted Origin headers with Allow-Credentials: true.",
                sample_path="/api/Users",
                sample_method="OPTIONS",
                sample_headers={"Origin": "https://attacker-domain.com", "Access-Control-Request-Method": "GET"}
            ),
            SecurityScenario(
                id="SCENARIO-H1-OPENAPI-02",
                title="Unauthenticated Swagger / OpenAPI Specification Disclosure",
                reference="HackerOne Disclosed #243412 & Bugcrowd Writeup",
                category="Info Disclosure",
                severity=FindingSeverity.LOW,
                technologies=["swagger", "openapi", "spring", "express", "fastapi", "rest"],
                summary="Publicly accessible OpenAPI, Swagger JSON, or GraphQL introspection schemas expose all internal endpoints, schemas, parameters, and deprecated routes.",
                precondition="Discovery of routes like /swagger.json, /openapi.json, /v2/api-docs, or /api-docs.",
                hypothesis_statement="The API publishes raw OpenAPI/Swagger definitions without authorization, exposing hidden administrative routes and parameter requirements.",
                recommended_remediation="Restrict access to API documentation behind authentication or disable interactive API docs in production environments.",
                sample_path="/api-docs",
                sample_method="GET"
            ),
            SecurityScenario(
                id="SCENARIO-H1-BOLA-03",
                title="BOLA / IDOR on Predictable Numeric Object Identifiers",
                reference="HackerOne Disclosed #682366 & OWASP API Top 10 API1:2023",
                category="API Security",
                severity=FindingSeverity.HIGH,
                technologies=["express", "node", "rest", "django", "laravel", "rails"],
                summary="REST API endpoints accept user-controlled IDs without validating that the authenticated session owns or is authorized to view the requested record.",
                precondition="Sequential or predictable IDs present in URLs like /api/Users/1, /rest/basket/1, or /api/Feedbacks/1.",
                hypothesis_statement="The application lacks object-level authorization checks, permitting unauthenticated or unauthorized retrieval of foreign user objects.",
                recommended_remediation="Implement robust authorization checks (ABAC or RBAC) on every database query and consider GUID/UUID identifiers.",
                sample_path="/api/Users/1",
                sample_method="GET"
            ),
            SecurityScenario(
                id="SCENARIO-H1-SECRETS-04",
                title="Client Bundle Hardcoded API Keys and Internal Routes",
                reference="HackerOne Disclosed #182749 & Modern SPA Research",
                category="Info Disclosure",
                severity=FindingSeverity.MEDIUM,
                technologies=["angular", "react", "vue", "javascript", "webpack"],
                summary="Single-Page Application JavaScript bundles (main.js, vendor.js) frequently leak development endpoints, AWS/Firebase API keys, or admin feature flags.",
                precondition="Frontend build tools bundle environment configurations or developer comments into public static assets.",
                hypothesis_statement="Client-side JavaScript bundles contain sensitive API tokens or unreferenced internal endpoints.",
                recommended_remediation="Ensure secrets remain strictly on the backend and exclude development source maps or test variables from production builds.",
                sample_path="/main.js",
                sample_method="GET"
            ),
            SecurityScenario(
                id="SCENARIO-H1-GRAPHQL-05",
                title="GraphQL Introspection Enabled & Batching Amplification",
                reference="HackerOne Disclosed #291531 & GraphQL Security Guide",
                category="GraphQL",
                severity=FindingSeverity.LOW,
                technologies=["graphql", "apollo", "node", "express"],
                summary="Production GraphQL services with enabled introspection query (__schema) reveal the entire data model, mutation operations, and private types.",
                precondition="Presence of /graphql endpoint returning schema data when queried.",
                hypothesis_statement="GraphQL introspection is exposed to anonymous users, providing attackers with a complete schema roadmap.",
                recommended_remediation="Disable introspection queries in production and enforce query depth/complexity limits.",
                sample_path="/graphql",
                sample_method="POST",
                sample_headers={"Content-Type": "application/json"},
                sample_body='{"query": "query { __schema { types { name } } }"}'
            ),
            SecurityScenario(
                id="SCENARIO-H1-HEADERS-06",
                title="Missing Anti-Clickjacking & Restrictive CSP Controls",
                reference="HackerOne Disclosed #147285 & OWASP Testing Guide",
                category="CORS & Headers",
                severity=FindingSeverity.LOW,
                technologies=["web", "html", "angular", "react", "express"],
                summary="Absence of X-Frame-Options: DENY and Content-Security-Policy frame-ancestors directive allows malicious web pages to frame the application for UI redressing.",
                precondition="HTTP responses missing X-Frame-Options and Content-Security-Policy.",
                hypothesis_statement="Target application can be embedded in an attacker-controlled iframe, leaving users vulnerable to clickjacking attacks.",
                recommended_remediation="Deploy Content-Security-Policy: frame-ancestors 'none'; and X-Frame-Options: DENY on all sensitive views.",
                sample_path="/",
                sample_method="GET"
            ),
            SecurityScenario(
                id="SCENARIO-H1-MASSASSIGN-07",
                title="Mass Assignment on Account Registration or Profile Update",
                reference="HackerOne Disclosed #492821 & OWASP API6:2023",
                category="API Security",
                severity=FindingSeverity.MEDIUM,
                technologies=["express", "node", "spring", "django", "laravel", "rails"],
                summary="Endpoints that bind incoming JSON request bodies directly to database models allow clients to inject unpermitted attributes like role: admin or is_verified: true.",
                precondition="Registration or profile update endpoints accepting JSON payloads.",
                hypothesis_statement="API automatically binds request parameters to internal model fields without an explicit parameter whitelist.",
                recommended_remediation="Use Data Transfer Objects (DTOs) with strict schema validation and parameter allow-lists.",
                sample_path="/api/Users",
                sample_method="POST",
                sample_headers={"Content-Type": "application/json"},
                sample_body='{"email": "test@researcher.local", "password": "SamplePassword123!", "role": "admin"}'
            ),
            SecurityScenario(
                id="SCENARIO-H1-DIRTRAVERSAL-08",
                title="Public FTP / Static Assets Directory Listing",
                reference="HackerOne Disclosed #307438 & Common Misconfig",
                category="Info Disclosure",
                severity=FindingSeverity.MEDIUM,
                technologies=["express", "nginx", "apache", "node"],
                summary="Public directory listing enabled on upload, static, or backup paths allows attackers to browse and download sensitive files.",
                precondition="Endpoints such as /ftp, /public, /uploads, or /static returning directory index listings.",
                hypothesis_statement="Static directory enables unauthenticated directory browsing, exposing backups, legal documents, or source code.",
                recommended_remediation="Disable directory browsing in server configuration and enforce strict 403 on index views.",
                sample_path="/ftp",
                sample_method="GET"
            ),
            SecurityScenario(
                id="SCENARIO-H1-SPRINGACTUATOR-09",
                title="Exposed Spring Boot Actuator Health & Metrics Endpoints",
                reference="HackerOne Disclosed #864619 & Spring Security Guide",
                category="Info Disclosure",
                severity=FindingSeverity.MEDIUM,
                technologies=["spring", "java", "actuator", "microservices"],
                summary="Spring Boot Actuator endpoints enabled without authentication leak internal service metrics, environment properties, and thread dumps.",
                precondition="Discovery of /actuator, /actuator/health, or /actuator/env endpoints returning 200 OK.",
                hypothesis_statement="The Spring Boot service exposes actuator telemetry and operational status without access controls.",
                recommended_remediation="Disable unnecessary actuator endpoints or secure them under management.endpoints.web.exposure.include and require operator authentication.",
                sample_path="/actuator/health",
                sample_method="GET"
            ),
            SecurityScenario(
                id="SCENARIO-H1-GITCONFIG-10",
                title="Publicly Exposed Git Metadata Repository (.git/HEAD)",
                reference="HackerOne Disclosed #173811 & Bugcrowd Writeup",
                category="Info Disclosure",
                severity=FindingSeverity.HIGH,
                technologies=["nginx", "apache", "node", "express", "php", "django"],
                summary="Improper web server document root deployment leaves the hidden .git directory accessible, allowing attackers to download complete application source code.",
                precondition="Request to /.git/HEAD returns HTTP 200 with ref: refs/heads/master or main.",
                hypothesis_statement="The application root exposes internal Git version control objects, risking complete repository reconstruction.",
                recommended_remediation="Block requests matching /\\.git.* in web server rules or ensure build artifacts exclude hidden VCS directories.",
                sample_path="/.git/HEAD",
                sample_method="GET"
            ),
            SecurityScenario(
                id="SCENARIO-H1-HOSTPOISON-11",
                title="Host Header Poisoning & Password Reset Link Hijacking",
                reference="HackerOne Disclosed #1150534 & PortSwigger Research",
                category="OAuth & Auth",
                severity=FindingSeverity.HIGH,
                technologies=["express", "node", "django", "laravel", "rails", "fastapi"],
                summary="When generating password reset links, web applications that trust untrusted Host or X-Forwarded-Host headers reflect the attacker's domain in reset tokens.",
                precondition="Application generates outbound emails or links using the incoming Host request header.",
                hypothesis_statement="The server generates domain-specific links based on user-controllable Host or X-Forwarded-Host headers.",
                recommended_remediation="Derive application domain strictly from server-side environment configurations rather than request headers.",
                sample_path="/rest/user/reset-password",
                sample_method="POST",
                sample_headers={"X-Forwarded-Host": "attacker.com", "Content-Type": "application/json"},
                sample_body='{"email": "researcher@example.com"}'
            ),
            SecurityScenario(
                id="SCENARIO-H1-SSRFWEBHOOK-12",
                title="Blind SSRF / Localhost Metadata Access via Webhook Callback",
                reference="HackerOne Disclosed #341876 & OWASP Top 10 A10:2021",
                category="API Security",
                severity=FindingSeverity.HIGH,
                technologies=["node", "express", "python", "fastapi", "django", "aws"],
                summary="Features that fetch external URLs (webhooks, avatar imports, PDF generators) without IP whitelisting can be tricked into probing internal cloud metadata (169.254.169.254) or internal services.",
                precondition="Presence of API endpoints taking url, callback_url, or webhook parameters.",
                hypothesis_statement="Backend service fetches client-supplied URLs without resolving and blocking private RFC 1918 and cloud link-local IP addresses.",
                recommended_remediation="Enforce strict DNS resolution, validate IP addresses against a private IP blacklist before connecting, and disable HTTP redirects.",
                sample_path="/api/webhooks",
                sample_method="POST",
                sample_headers={"Content-Type": "application/json"},
                sample_body='{"webhook_url": "http://169.254.169.254/latest/meta-data/"}'
            ),
            SecurityScenario(
                id="SCENARIO-H1-RATELIMITBYPASS-13",
                title="Authentication Rate Limiting Bypass via IP Spoofing Headers",
                reference="HackerOne Disclosed #496357 & Bounty Methodology",
                category="OAuth & Auth",
                severity=FindingSeverity.MEDIUM,
                technologies=["express", "node", "nginx", "cloudflare", "fastapi"],
                summary="Login endpoints enforcing brute-force protection keyed solely on client IP can be bypassed if reverse proxies honor spoofed X-Forwarded-For or Client-IP headers.",
                precondition="Login API endpoint returning 429 Too Many Requests upon rapid submissions.",
                hypothesis_statement="Rate limiting middleware trusts client-supplied IP forwarding headers instead of the direct socket remote address.",
                recommended_remediation="Configure reverse proxies to strip untrusted upstream headers and derive client IP only from trusted proxy hops.",
                sample_path="/rest/user/login",
                sample_method="POST",
                sample_headers={"X-Forwarded-For": "127.0.0.1", "Content-Type": "application/json"},
                sample_body='{"email": "admin@target.local", "password": "wrong"}'
            ),
            SecurityScenario(
                id="SCENARIO-H1-PROTOTYPEPOLLUTION-14",
                title="Client-Side & Server-Side Prototype Pollution via Object Merge",
                reference="HackerOne Disclosed #396395 & Olivier Arteau Research",
                category="API Security",
                severity=FindingSeverity.HIGH,
                technologies=["node", "express", "javascript", "lodash", "angular"],
                summary="Recursive JSON object merging or query string decoders without property filtering allow injecting __proto__ or constructor.prototype properties, leading to denial of service or logic bypass.",
                precondition="Node.js/Express backend processing complex nested JSON payloads or query strings.",
                hypothesis_statement="Object merge utility modifies Object.prototype when processing payload containing __proto__ attributes.",
                recommended_remediation="Freeze Object.prototype, use Map objects, or validate against __proto__ / constructor keys.",
                sample_path="/api/profile",
                sample_method="PUT",
                sample_headers={"Content-Type": "application/json"},
                sample_body='{"__proto__": {"isAdmin": true}}'
            ),
            SecurityScenario(
                id="SCENARIO-H1-CACHEDECLEPTION-15",
                title="Web Cache Deception via Static File Extension Appending",
                reference="HackerOne Disclosed #409370 & Omer Gil Research",
                category="CORS & Headers",
                severity=FindingSeverity.MEDIUM,
                technologies=["cloudflare", "akamai", "nginx", "express", "angular"],
                summary="Appending static extensions (e.g., .css, .js, .png) to sensitive dynamic endpoints (e.g., /account.css) causes caching reverse proxies to store the authenticated response publicly.",
                precondition="Caching proxy or CDN in front of application that caches based on URL path suffix.",
                hypothesis_statement="Intermediate caching layer caches private account response due to static extension appended to path.",
                recommended_remediation="Configure cache rules based on explicit Cache-Control headers rather than URL file extensions alone.",
                sample_path="/rest/user/whoami.css",
                sample_method="GET"
            ),
            SecurityScenario(
                id="SCENARIO-H1-ENVLEAK-16",
                title="Root Environment File & Backup Disclosure (.env / config.json)",
                reference="HackerOne Disclosed #264350 & Common Misconfig",
                category="Info Disclosure",
                severity=FindingSeverity.CRITICAL,
                technologies=["node", "express", "django", "laravel", "docker"],
                summary="Direct access to root configuration files (.env, .env.backup, docker-compose.yml) reveals production database credentials, AWS keys, and encryption secrets.",
                precondition="Web root containing sensitive dot-files accessible over plain HTTP.",
                hypothesis_statement="Environment configuration file .env is served directly by the web server without access restriction.",
                recommended_remediation="Store environment files outside the web root and configure web server rules to deny access to all hidden files.",
                sample_path="/.env",
                sample_method="GET"
            )
        ]

        for s in seed_data:
            self.scenarios[s.id] = s

    def get_all_scenarios(self) -> List[SecurityScenario]:
        """Return all registered scenarios."""
        return list(self.scenarios.values())

    def get_scenario(self, scenario_id: str) -> Optional[SecurityScenario]:
        """Find scenario by its identifier."""
        return self.scenarios.get(scenario_id)

    def find_applicable_scenarios(
        self,
        detected_tech: List[str],
        endpoints: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Match detected technologies and endpoints to relevant writeup scenarios.
        
        Returns scenarios ranked by relevance score.
        """
        tech_set = {t.lower().strip() for t in detected_tech}
        endpoints_str = " ".join(endpoints or []).lower()

        results = []
        for scenario in self.scenarios.values():
            score = 0
            matched_tech = []

            # 1. Tech matches
            for t in scenario.technologies:
                if t.lower() in tech_set or any(t.lower() in dt for dt in tech_set):
                    score += 2
                    matched_tech.append(t)

            # 2. Endpoint path matches
            if scenario.sample_path.lower() in endpoints_str:
                score += 3

            # 3. Always include general web header/info disclosure scenarios with baseline score
            if scenario.category in ["CORS & Headers", "Info Disclosure"]:
                score += 1

            if score > 0:
                results.append({
                    "scenario": scenario,
                    "relevance_score": score,
                    "matched_tech": matched_tech
                })

        # Sort by relevance score descending
        results.sort(key=lambda x: x["relevance_score"], reverse=True)
        return results

    def import_custom_writeup(
        self,
        title: str,
        technologies: List[str],
        category: str,
        hypothesis_statement: str,
        summary: str,
        reference: str = "User Contributed Writeup",
        severity: FindingSeverity = FindingSeverity.MEDIUM,
        sample_path: str = "/",
        sample_method: str = "GET",
        sample_headers: Optional[Dict[str, str]] = None,
        sample_body: Optional[str] = None
    ) -> SecurityScenario:
        """Register a user-submitted writeup or scenario into the knowledge base."""
        custom_id = f"SCENARIO-CUSTOM-{len(self.scenarios) + 1:02d}"
        scenario = SecurityScenario(
            id=custom_id,
            title=title,
            reference=reference,
            category=category,
            severity=severity,
            technologies=[t.lower().strip() for t in technologies],
            summary=summary,
            precondition="User defined precondition",
            hypothesis_statement=hypothesis_statement,
            recommended_remediation="Verify input sanitization, access controls, and least privilege.",
            sample_path=sample_path,
            sample_method=sample_method.upper(),
            sample_headers=sample_headers or {},
            sample_body=sample_body
        )
        self.scenarios[custom_id] = scenario
        return scenario
