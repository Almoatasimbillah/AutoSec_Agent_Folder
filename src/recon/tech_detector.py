"""Technology Fingerprinting Engine (Doc 06 & Doc 17).

Identifies web servers, backend frameworks, CMS platforms, and technologies
from response headers, cookies, and DOM markers.
"""

from typing import Dict, List, Set, Any
import re


class TechnologyDetector:
    """Detects technologies from HTTP response metadata."""

    HEADER_RULES = {
        "Server": [
            ("nginx", "Nginx"),
            ("apache", "Apache"),
            ("cloudflare", "Cloudflare"),
            ("microsoft-iis", "Microsoft IIS"),
            ("litespeed", "LiteSpeed"),
            ("caddy", "Caddy"),
            ("gunicorn", "Gunicorn"),
            ("uvicorn", "Uvicorn"),
        ],
        "X-Powered-By": [
            ("express", "Express.js"),
            ("php", "PHP"),
            ("asp.net", "ASP.NET"),
            ("next.js", "Next.js"),
            ("django", "Django"),
        ]
    }

    COOKIE_RULES = {
        "phpsessid": "PHP",
        "csrftoken": "Django",
        "laravel_session": "Laravel",
        "xsrf-token": "Laravel/Vue",
        "connect.sid": "Express.js",
        "jsessionid": "Java/Spring",
        "asp.net_sessionid": "ASP.NET",
        "_rails_session": "Ruby on Rails",
    }

    BODY_RULES = [
        (r"wp-content|wp-includes", "WordPress"),
        (r"data-reactroot|id=[\"']__next[\"']|_next/static", "React / Next.js"),
        (r"data-v-[a-zA-Z0-9]+|vue\.js", "Vue.js"),
        (r"ng-version=", "Angular"),
        (r"Whitelabel Error Page", "Spring Boot"),
        (r"swagger-ui|api-docs", "Swagger / OpenAPI"),
    ]

    @classmethod
    def detect_from_response(
        cls,
        headers: Dict[str, str],
        cookies: Dict[str, str] = None,
        body: str = ""
    ) -> List[str]:
        """Analyze headers, cookies, and body to identify technologies."""
        detected: Set[str] = set()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        cookies_lower = {k.lower(): v for k, v in (cookies or {}).items()}

        # 1. Header checks
        for header_name, rules in cls.HEADER_RULES.items():
            header_val = headers_lower.get(header_name.lower())
            if header_val:
                for keyword, tech_name in rules:
                    if keyword in header_val:
                        detected.add(tech_name)

        # 2. Cookie signature checks
        for cookie_name, tech_name in cls.COOKIE_RULES.items():
            if cookie_name in cookies_lower:
                detected.add(tech_name)

        # 3. Body heuristic checks
        if body:
            for pattern, tech_name in cls.BODY_RULES:
                if re.search(pattern, body, re.IGNORECASE):
                    detected.add(tech_name)

        return sorted(list(detected))
