import { hash } from "./canonical.ts";
import type { Plan, PlanStep } from "./types.ts";

/**
 * Build a plan from steps and compute its plan_hash = sha256(JCS(plan)).
 * (SPEC §9 step 2.) The Planner has no authority; this is a proposal only.
 */
export function proposePlan(steps: PlanStep[]): { plan: Plan; plan_hash: string } {
  if (!Array.isArray(steps) || steps.length === 0) {
    throw new Error("proposePlan: a plan MUST have at least one step");
  }
  const plan: Plan = { kind: "vcp.plan", steps };
  return { plan, plan_hash: planHash(plan) };
}

export function planHash(plan: Plan): string {
  return hash(plan);
}
