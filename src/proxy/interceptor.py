"""Passive Traffic Interception Proxy (Doc 03, Doc 10, Doc 16).

Runs a lightweight local HTTP proxy on 127.0.0.1:8085 that transparently forwards
browser traffic, logs in-scope requests/responses to the engagement store, and
passively analyzes headers, authentication tokens, and endpoints without active attacks.
"""

import asyncio
import time
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse
import httpx
from pydantic import BaseModel, Field

from ..policy.scope_engine import ScopeEngine
from ..knowledge.target_model import TargetModelManager


class CapturedTrafficItem(BaseModel):
    """Normalized HTTP transaction recorded by the passive proxy."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().strftime("%H:%M:%S"))
    method: str
    url: str
    host: str
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: int = 200
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body_length: int = 0
    latency_ms: float = 0.0
    is_in_scope: bool = True
    detected_tokens: List[str] = Field(default_factory=list)
    security_warnings: List[str] = Field(default_factory=list)


class PassiveInterceptionProxy:
    """Async local HTTP proxy that passively records and evaluates web traffic."""

    def __init__(
        self,
        scope_engine: Optional[ScopeEngine] = None,
        target_model: Optional[TargetModelManager] = None,
        host: str = "127.0.0.1",
        port: int = 8085
    ):
        self.scope_engine = scope_engine
        self.target_model = target_model
        self.host = host
        self.port = port
        self.is_running = False
        self.server: Optional[asyncio.AbstractServer] = None
        self.traffic_history: List[CapturedTrafficItem] = []
        self._max_history = 500

    async def start(self):
        """Start the async proxy listener."""
        if self.is_running:
            return
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self.is_running = True

    async def stop(self):
        """Stop the proxy listener."""
        if not self.is_running or not self.server:
            return
        self.server.close()
        await self.server.wait_closed()
        self.is_running = False
        self.server = None

    def get_traffic(self, limit: int = 100, in_scope_only: bool = False) -> List[CapturedTrafficItem]:
        """Retrieve captured traffic items ordered by most recent."""
        items = self.traffic_history
        if in_scope_only:
            items = [t for t in items if t.is_in_scope]
        return items[-limit:][::-1]

    def clear_traffic(self):
        """Clear traffic buffer."""
        self.traffic_history.clear()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle individual client HTTP connections."""
        try:
            raw_line = await reader.readline()
            if not raw_line:
                writer.close()
                await writer.wait_closed()
                return

            line = raw_line.decode("utf-8", errors="replace").strip()
            parts = line.split()
            if len(parts) < 2:
                writer.close()
                await writer.wait_closed()
                return

            method, raw_target = parts[0].upper(), parts[1]

            # Read headers
            headers: Dict[str, str] = {}
            content_length = 0
            while True:
                header_line = await reader.readline()
                if not header_line or header_line == b"\r\n" or header_line == b"\n":
                    break
                decoded_header = header_line.decode("utf-8", errors="replace").strip()
                if ":" in decoded_header:
                    k, v = decoded_header.split(":", 1)
                    headers[k.strip()] = v.strip()
                    if k.strip().lower() == "content-length":
                        try:
                            content_length = int(v.strip())
                        except ValueError:
                            pass

            # Read body if present
            body_text: Optional[str] = None
            if content_length > 0 and content_length < 1000000:
                body_bytes = await reader.readexactly(content_length)
                body_text = body_bytes.decode("utf-8", errors="replace")

            # CONNECT Method (HTTPS Tunnel)
            if method == "CONNECT":
                # Acknowledge CONNECT
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # Normalize Target URL
            if raw_target.startswith("http://") or raw_target.startswith("https://"):
                full_url = raw_target
            else:
                host_hdr = headers.get("Host", "localhost")
                full_url = f"http://{host_hdr}{raw_target}"

            parsed_url = urlparse(full_url)
            host = parsed_url.hostname or "localhost"

            # Check Scope
            is_in_scope = True
            if self.scope_engine:
                scope_res = self.scope_engine.evaluate(full_url)
                is_in_scope = scope_res.is_allowed

            # Forward request to upstream target
            start_time = time.time()
            resp_status = 502
            resp_headers: Dict[str, str] = {}
            resp_body = b""

            try:
                # Remove hop-by-hop headers
                fwd_headers = {k: v for k, v in headers.items() if k.lower() not in {"host", "connection", "proxy-connection"}}
                async with httpx.AsyncClient(verify=False, timeout=12.0, follow_redirects=False) as http_client:
                    upstream_resp = await http_client.request(
                        method=method,
                        url=full_url,
                        headers=fwd_headers,
                        content=body_text.encode("utf-8") if body_text else None
                    )
                    resp_status = upstream_resp.status_code
                    resp_headers = dict(upstream_resp.headers)
                    resp_body = upstream_resp.content
            except Exception as ex:
                resp_body = f"Proxy Forwarding Error: {str(ex)}".encode("utf-8")

            latency = round((time.time() - start_time) * 1000, 2)

            # Send response back to browser
            status_line = f"HTTP/1.1 {resp_status} OK\r\n"
            writer.write(status_line.encode("utf-8"))
            for hk, hv in resp_headers.items():
                if hk.lower() not in {"transfer-encoding", "connection"}:
                    writer.write(f"{hk}: {hv}\r\n".encode("utf-8"))
            writer.write(f"Content-Length: {len(resp_body)}\r\n\r\n".encode("utf-8"))
            writer.write(resp_body)
            await writer.drain()

            # Passive Token & Vulnerability Analysis
            tokens = []
            warnings = []

            # Check for tokens in headers
            for hk, hv in headers.items():
                if "authorization" in hk.lower() and "bearer" in hv.lower():
                    tokens.append("Bearer JWT in Header")
                if "cookie" in hk.lower() and ("session" in hv.lower() or "token" in hv.lower()):
                    tokens.append("Session Cookie in Header")

            # Check response headers for security deficiencies
            if is_in_scope:
                if "content-security-policy" not in {k.lower() for k in resp_headers}:
                    warnings.append("Missing Content-Security-Policy")
                if "x-frame-options" not in {k.lower() for k in resp_headers}:
                    warnings.append("Missing X-Frame-Options (Clickjacking Risk)")
                if "access-control-allow-origin" in {k.lower() for k in resp_headers}:
                    if resp_headers.get("access-control-allow-origin") == "*":
                        warnings.append("CORS Wildcard Allowed")

            # Record in traffic history
            item = CapturedTrafficItem(
                method=method,
                url=full_url,
                host=host,
                request_headers=headers,
                request_body=body_text[:1000] if body_text else None,
                response_status=resp_status,
                response_headers=resp_headers,
                response_body_length=len(resp_body),
                latency_ms=latency,
                is_in_scope=is_in_scope,
                detected_tokens=tokens,
                security_warnings=warnings
            )
            self.traffic_history.append(item)
            if len(self.traffic_history) > self._max_history:
                self.traffic_history.pop(0)

            # Auto-register endpoint in TargetModel
            if self.target_model and is_in_scope and parsed_url.path:
                try:
                    apps = self.target_model.get_applications()
                    app_id = apps[0].id if apps else None
                    if app_id:
                        self.target_model.add_endpoint(
                            application_id=app_id,
                            method=method,
                            path=parsed_url.path
                        )
                except Exception:
                    pass

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
