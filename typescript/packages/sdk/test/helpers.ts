import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

/** Absolute path to the shared conformance vectors directory. */
export const VECTORS_DIR = resolve(here, "../../../../conformance/vectors");

export function loadVector<T = unknown>(name: string): T {
  const p = resolve(VECTORS_DIR, name);
  return JSON.parse(readFileSync(p, "utf8")) as T;
}
