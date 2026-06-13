"""A sample Capability Provider exposing the §16 capabilities.

The Provider executes a capability *within the bounds of a grant* (§8) and
returns a Provider-signed attestation (§9). It verifies the grant audience and
recomputes ``argument_hash`` before committing, exactly as §8 requires, and
honors ``dry_run`` for the write-reversible ``calendar.create_event``.

It is a thin multiplexer over :class:`vcp_gateway.InMemoryProvider`: one signed
sub-provider per capability id, sharing one provider signing key.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from vcp_gateway import InMemoryProvider
from vcp_sdk.signing import Signer, default_signer

from . import capabilities


class SampleProvider:
    """Routes invocations to the right §16 capability handler and signs results.

    Constructed from a name->manifest map (so it shares identity with what the
    Gateway verifies). Exposes :meth:`for_capability` returning the concrete
    :class:`~vcp_gateway.InMemoryProvider` bound to one capability id, which is
    what :meth:`vcp_gateway.Gateway.invoke` expects.
    """

    def __init__(
        self,
        manifests: Mapping[str, Mapping[str, Any]],
        signer: Optional[Signer] = None,
    ) -> None:
        self.signer = signer or default_signer()
        # capability_id -> InMemoryProvider
        self._by_id: dict[str, InMemoryProvider] = {}
        # name -> capability_id
        self._id_by_name: dict[str, str] = {}
        for name, manifest in manifests.items():
            cap_id = manifest["capability"]["id"]
            handler = capabilities.HANDLERS[name]
            self._by_id[cap_id] = InMemoryProvider(
                cap_id, signer=self.signer, handler=handler
            )
            self._id_by_name[name] = cap_id

    @property
    def verifier(self):
        """The attestation verifier the Gateway uses to validate signatures."""
        return self.signer.verifier()

    def capability_id_for(self, name: str) -> str:
        return self._id_by_name[name]

    def for_capability(self, capability_id: str) -> InMemoryProvider:
        prov = self._by_id.get(capability_id)
        if prov is None:
            raise KeyError(f"no provider for capability {capability_id!r}")
        return prov
