import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

export const VECTORS_DIR = resolve(here, "../../../../conformance/vectors");

export function loadVector<T = unknown>(name: string): T {
  return JSON.parse(readFileSync(resolve(VECTORS_DIR, name), "utf8")) as T;
}
