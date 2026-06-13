import { test } from "node:test";
import assert from "node:assert/strict";
import type { InterfaceBlock } from "@vcp/sdk";
import {
  interfaceContentHash,
  verifyInterfaceHash,
  checkHostAction,
} from "../src/interface.ts";

const CALENDAR_CREATE = "vcp:cap:calendar.create_event@sha256:" + "9".repeat(64);
const CALENDAR_DELETE = "vcp:cap:calendar.delete_event@sha256:" + "8".repeat(64);

function pickerInterface(bytes: string): InterfaceBlock {
  return {
    surface: "vcp:ui:example.calendar.picker@" + interfaceContentHash(bytes),
    content_hash: interfaceContentHash(bytes),
    render: "html-sandboxed",
    csp: { "default-src": ["'none'"], "connect-src": ["https://calendar.example.com"] },
    permissions: [],
    host_actions: [CALENDAR_CREATE],
    model_visible: false,
  };
}

test("§22 / §18 test 18: UI artifact swap => INTERFACE_HASH_MISMATCH", () => {
  const original = "<html><body>Pick a slot</body></html>";
  const iface = pickerInterface(original);

  // Rendering the exact signed bytes verifies.
  const ok = verifyInterfaceHash(iface, original);
  assert.equal(ok.decision, "allow");
  assert.equal(ok.reason_code, "OK");

  // A swapped artifact (even a one-byte change) is a content-address failure.
  const swapped = "<html><body>Pick a slot.</body></html>";
  const bad = verifyInterfaceHash(iface, swapped);
  assert.equal(bad.decision, "deny");
  assert.equal(bad.reason_code, "INTERFACE_HASH_MISMATCH");
});

test("§22: UI-initiated call outside host_actions is rejected; allowlisted call passes", () => {
  const iface = pickerInterface("<html></html>");

  // The picker may create events (declared affordance).
  const allowed = checkHostAction(iface, CALENDAR_CREATE);
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.reason_code, "OK");

  // It may NOT initiate a delete: not in host_actions ⇒ rejected before policy.
  const blocked = checkHostAction(iface, CALENDAR_DELETE);
  assert.equal(blocked.decision, "deny");
  assert.equal(blocked.reason_code, "SANDBOX_VIOLATION");
});
