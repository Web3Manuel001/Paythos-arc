/**
 * Zero-dependency `.env` loader (Node ≥ 18 compatible).
 * Loads `sdk/typescript/.env` when present; NEVER overrides variables that are
 * already set in the real environment (explicit export wins, fail-safe order).
 * Secrets hygiene (AGENTS.md rule 5): values parsed here are never logged.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export function loadDotEnv(cwd: string = process.cwd()): number {
  const path = resolve(cwd, ".env");
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return 0;
  }
  let applied = 0;
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!key || !value) continue;
    if (process.env[key] === undefined) {
      process.env[key] = value;
      applied += 1;
    }
  }
  return applied;
}
