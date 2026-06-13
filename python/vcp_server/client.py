"""A thin stdlib VCP-HTTP client (SPEC §15) for the demo and tests.

Speaks the `VCP-HTTP` profile over ``http.client``: it always sends the mandatory
``vcp-version`` header and, for plan/apply, the ``vcp-capability-hash`` header
pinning the capability index it last fetched and verified. There are no implicit
sessions — every call is self-contained.
"""

from __future__ import annotations

import http.client
import json
from typing import Any, Mapping, Optional
from urllib.parse import urlparse

VCP_VERSION = "0.1"


class VCPClient:
    """A minimal VCP-HTTP client. ``capability_hash`` pins the verified index."""

    def __init__(self, base_url: str) -> None:
        p = urlparse(base_url)
        self.host = p.hostname
        self.port = p.port
        self.capability_hash: Optional[str] = None

    def _conn(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection(self.host, self.port, timeout=10)

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        *,
        send_cap_hash: bool = False,
        cap_hash_override: Optional[str] = None,
        omit_version: bool = False,
    ) -> tuple[int, dict, dict]:
        headers = {"Content-Type": "application/json"}
        if not omit_version:
            headers["vcp-version"] = VCP_VERSION
        if send_cap_hash:
            headers["vcp-capability-hash"] = cap_hash_override or self.capability_hash or ""
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        conn = self._conn()
        try:
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            data = json.loads(raw.decode("utf-8")) if raw else {}
            return resp.status, data, dict(resp.getheaders())
        finally:
            conn.close()

    # -- discovery -------------------------------------------------------- #
    def discovery(self) -> dict:
        _, data, _ = self._request("GET", "/.well-known/vcp-provider")
        return data

    def capabilities(self) -> dict:
        status, data, headers = self._request("GET", "/vcp/capabilities")
        # Pin the capability-index hash the server reports (§4/§15).
        self.capability_hash = headers.get("vcp-capability-hash")
        return data

    def manifest(self, name: str) -> dict:
        _, data, _ = self._request("GET", f"/vcp/manifest/{name}")
        return data

    # -- plan / apply ----------------------------------------------------- #
    def plan(self, plan_body: Mapping[str, Any], **kw) -> tuple[int, dict]:
        status, data, _ = self._request("POST", "/vcp/plan", plan_body, send_cap_hash=True, **kw)
        return status, data

    def approve(self, plan_hash: str) -> tuple[int, dict]:
        status, data, _ = self._request("POST", "/vcp/approve", {"plan_hash": plan_hash})
        return status, data

    def apply(self, plan_hash: str, **kw) -> tuple[int, dict]:
        status, data, _ = self._request(
            "POST", "/vcp/apply", {"plan_hash": plan_hash}, send_cap_hash=True, **kw
        )
        return status, data

    # -- audit ------------------------------------------------------------ #
    def audit(self) -> dict:
        _, data, _ = self._request("GET", "/vcp/audit")
        return data
