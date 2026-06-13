"""VCP-HTTP server + sample provider + runnable §16 demo.

Built ON TOP of :mod:`vcp_sdk` and :mod:`vcp_gateway` (which hold the protocol
logic and authority). This package adds only transport and a worked scenario:

* :class:`VCPHTTPServer` — a stateless `VCP-HTTP` gateway server (SPEC §15) on the
  stdlib :mod:`http.server` (no Flask/FastAPI). Endpoints: discovery,
  capability index, plan, apply, audit. Each request is one authorization
  decision; mandatory ``vcp-version`` / ``vcp-capability-hash`` headers.
* :class:`SampleProvider` — the §16 capabilities (email.search, email.read,
  calendar.find_free_slots, calendar.create_event) returning signed attestations.
* :class:`VCPClient` — a thin stdlib `http.client` client for the demo/tests.
* :mod:`vcp_server.demo` — ``python -m vcp_server.demo`` drives the full §16
  scenario end to end over HTTP, including the injected-instruction containment.
* :mod:`vcp_server.demo_obo` — ``python -m vcp_server.demo_obo`` drives the §26
  multi-provider on-behalf-of fan-out: one Gateway, three in-process Providers
  (gmail/linear/slack), one approval, per-provider token exchange (RFC 8693),
  one scoped grant per write with its delegation chain, and the blocked
  confidential->external cross-provider data flow (DATA_FLOW_FORBIDDEN).

No new third-party dependencies; the optional ``cryptography`` extra still
applies (real Ed25519 if installed, labelled HMAC fallback otherwise).
"""

from __future__ import annotations

from .capabilities import ISSUER, build_all_manifests
from .client import VCPClient
from .http_server import VCPHTTPServer, VCPServerState
from .provider import SampleProvider

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "VCPHTTPServer",
    "VCPServerState",
    "VCPClient",
    "SampleProvider",
    "build_all_manifests",
    "ISSUER",
]
