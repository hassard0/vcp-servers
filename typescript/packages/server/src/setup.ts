import { Ed25519Signer } from "@vcp/sdk";
import { DefaultPolicy } from "@vcp/gateway";
import { buildSignedCapabilities } from "./manifests.ts";
import { WorkspaceProvider } from "./provider.ts";
import { GatewayEngine } from "./engine.ts";

/**
 * Wire up a fully configured GatewayEngine for the §16 demo: one provider key
 * (signs manifests + attestations), one gateway key (mints grants + signs
 * audit), the four signed capabilities, the workspace provider, and the
 * taint/data-flow-aware DefaultPolicy.
 *
 * The DefaultPolicy's metadataSinks include calendar.create_event (the §16
 * allowed email→calendar metadata flow) and its externalSinks include
 * email.send / slack.post_message (the forbidden exfiltration sinks).
 */
export async function buildEngine(): Promise<GatewayEngine> {
  const providerSigner = Ed25519Signer.generate();
  const gatewaySigner = Ed25519Signer.generate();

  const caps = await buildSignedCapabilities(providerSigner);
  const nameById = new Map<string, string>();
  for (const m of caps.manifests) nameById.set(m.capability.id, m.capability.name);

  const provider = new WorkspaceProvider(providerSigner, nameById);
  const policy = new DefaultPolicy({
    metadataSinks: ["calendar.create_event"],
    externalSinks: ["email.send", "slack.post_message", "http.post", "email.forward"],
  });

  return new GatewayEngine({
    caps,
    manifestTrustedKey: providerSigner.publicKey(),
    trustedIssuers: [caps.issuer],
    policy,
    gatewaySigner,
    provider,
    subject: "user:alice",
    model: "agent:planner",
    host: "demo.host",
  });
}
