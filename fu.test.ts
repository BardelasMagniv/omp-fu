import { test, expect } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { reconcileDb, type Report } from "./fu-policy.ts";

function fixture(run: (db: Database, file: string, now: number) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "fu-isolated-"));
  const file = join(dir, "agent.db");
  const db = new Database(file);
  const now = Date.now();
  try {
    db.run("CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, provider TEXT, credential_type TEXT, data TEXT, identity_key TEXT, disabled_cause TEXT, updated_at INTEGER)");
    db.run("CREATE TABLE auth_credential_blocks (credential_id INTEGER, provider_key TEXT, block_scope TEXT, blocked_until_ms INTEGER, updated_at INTEGER, PRIMARY KEY (credential_id, provider_key, block_scope))");
    run(db, file, now);
  } finally { db.close(); rmSync(dir, { recursive: true, force: true }); }
}
function row(db: Database, id: number, provider: string, email: string, now: number, disabled: string | null = null): void {
  db.query("INSERT INTO auth_credentials VALUES (?, ?, ?, ?, ?, ?, ?)").run(id, provider, "oauth", JSON.stringify({ email, access: "secret-never-log" }), `email:${email}`, disabled, Math.floor(now / 1000) - 90);
}
function block(db: Database, id: number, provider: string, scope: string, now: number): void {
  db.query("INSERT INTO auth_credential_blocks VALUES (?, ?, ?, ?, ?)").run(id, `${provider}:oauth`, scope, now + 500000, Math.floor(now / 1000) - 70);
}
function usage(provider: string, email: string, now: number, fractions: number[], scope = ""): Report {
  return { provider, fetchedAt: now, metadata: { email }, limits: fractions.map((usedFraction, i) => ({
    id: `${provider}:${scope || "window"}:${i}`, scope: { provider }, amount: { usedFraction }, status: "ok",
  })) };
}
test("only exact healthy credential block is deleted, not exhausted or disabled neighbors", () => fixture((db, file, now) => {
  row(db, 1, "vendor", "one@example.test", now);
  row(db, 2, "vendor", "two@example.test", now);
  row(db, 3, "vendor", "off@example.test", now, "revoked");
  for (const id of [1, 2, 3]) block(db, id, "vendor", "", now);
  const results = reconcileDb(file, [usage("vendor", "one@example.test", now, [0.2, 0.4]),
    usage("vendor", "two@example.test", now, [1]), usage("vendor", "off@example.test", now, [0])], 0.05, now);
  expect(results.map(result => result.decision.kind)).toEqual(["corrected", "unchanged", "skipped"]);
  expect((db.query("SELECT credential_id FROM auth_credential_blocks ORDER BY credential_id").all() as Array<{credential_id: number}>).map(r => r.credential_id)).toEqual([2, 3]);
  expect(JSON.stringify(results)).not.toContain("secret-never-log");
}));
test("ambiguous identity, missing scoped meter, stale report and reserve fail closed", () => fixture((db, file, now) => {
  row(db, 1, "vendor", "shared@example.test", now);
  row(db, 2, "vendor", "shared@example.test", now);
  row(db, 3, "vendor", "tier@example.test", now);
  row(db, 4, "vendor", "stale@example.test", now);
  row(db, 5, "vendor", "reserve@example.test", now);
  block(db, 1, "vendor", "", now); block(db, 2, "vendor", "", now);
  block(db, 3, "vendor", "tier:premium", now); block(db, 4, "vendor", "", now); block(db, 5, "vendor", "", now);
  const stale = usage("vendor", "stale@example.test", now - 180000, [0.1]);
  const results = reconcileDb(file, [usage("vendor", "shared@example.test", now, [0.1]),
    usage("vendor", "tier@example.test", now, [0.1]), stale,
    usage("vendor", "reserve@example.test", now, [0.98])], 0.05, now);
  expect(results.map(result => result.decision.kind)).toEqual(["skipped", "skipped", "skipped", "skipped", "unchanged"]);
  expect(db.query("SELECT count(*) AS n FROM auth_credential_blocks").get()).toEqual({ n: 5 });
}));
test("Codex chat healing preserves exhausted Spark and shared mirror; never deletes shared directly", () => fixture((db, file, now) => {
  row(db, 1, "openai-codex", "coder@example.test", now);
  block(db, 1, "openai-codex", "chat", now);
  block(db, 1, "openai-codex", "spark", now);
  block(db, 1, "openai-codex", "shared", now);
  // Reproduce the installed SQLite meter DELETE trigger: rebuild shared from surviving meters.
  db.run(`CREATE TRIGGER codex_meter_delete AFTER DELETE ON auth_credential_blocks
    WHEN OLD.provider_key = "openai-codex:oauth" AND OLD.block_scope IN ("chat", "spark")
    BEGIN
      DELETE FROM auth_credential_blocks WHERE credential_id = OLD.credential_id AND provider_key = OLD.provider_key AND block_scope = "shared";
      INSERT INTO auth_credential_blocks SELECT OLD.credential_id, OLD.provider_key, "shared", MAX(blocked_until_ms), MAX(updated_at)
        FROM auth_credential_blocks WHERE credential_id = OLD.credential_id AND provider_key = OLD.provider_key
        AND block_scope IN ("chat", "spark") GROUP BY credential_id, provider_key;
    END`);
  const report: Report = { provider: "openai-codex", fetchedAt: now,
    metadata: { email: "coder@example.test", meterStates: { chat: { allowed: true, limitReached: false }, spark: { allowed: false, limitReached: true } } },
    limits: [{ id: "openai-codex:primary", scope: { provider: "openai-codex" }, amount: { usedFraction: 0.2 } },
      { id: "openai-codex:spark:primary", scope: { provider: "openai-codex" }, amount: { usedFraction: 1 } }] };
  const results = reconcileDb(file, [report], 0.05, now);
  expect(results.map(result => result.decision.kind)).toEqual(["corrected", "skipped", "skipped"]);
  expect((db.query("SELECT block_scope FROM auth_credential_blocks ORDER BY block_scope").all() as Array<{block_scope: string}>).map(r => r.block_scope)).toEqual(["shared", "spark"]);
}));

test("identity qualifiers are exact and account IDs remain case-sensitive", () => fixture((db, file, now) => {
  row(db, 1, "vendor", "shared@example.test", now);
  row(db, 2, "vendor", "shared@example.test", now);
  db.query("UPDATE auth_credentials SET data = ?, identity_key = ? WHERE id = ?")
    .run(JSON.stringify({email:"shared@example.test",orgId:"OrgA",access:"secret"}), "email:shared@example.test|org:OrgA", 1);
  db.query("UPDATE auth_credentials SET data = ?, identity_key = ? WHERE id = ?")
    .run(JSON.stringify({email:"shared@example.test",orgId:"OrgB",access:"secret"}), "email:shared@example.test|org:OrgB", 2);
  block(db, 1, "vendor", "", now); block(db, 2, "vendor", "", now);
  const report = usage("vendor", "shared@example.test", now, [0.1]);
  report.metadata = { email:"shared@example.test", orgId:"OrgA" };
  expect(reconcileDb(file, [report], 0.05, now).map(result => result.decision.kind)).toEqual(["corrected", "skipped"]);
  row(db, 3, "vendor", "", now);
  db.query("UPDATE auth_credentials SET data = ?, identity_key = ? WHERE id = ?")
    .run(JSON.stringify({accountId:"TenantX",access:"secret"}), "account:TenantX", 3);
  block(db, 3, "vendor", "", now);
  const wrongCase = usage("vendor", "", now, [0.1]);
  wrongCase.metadata = { accountId:"tenantx" };
  expect(reconcileDb(file, [wrongCase], 0.05, now).find(result => result.block.credential_id === 3)?.decision.kind).toBe("skipped");
}));
test("a delete trigger changing identity rolls back the block deletion", () => fixture((db, file, now) => {
  row(db, 1, "vendor", "one@example.test", now); block(db, 1, "vendor", "", now);
  db.run(`CREATE TRIGGER poison BEFORE DELETE ON auth_credential_blocks BEGIN
    UPDATE auth_credentials SET disabled_cause = "changed" WHERE id = OLD.credential_id;
  END`);
  const result = reconcileDb(file, [usage("vendor", "one@example.test", now, [0.2])], 0.05, now);
  expect(result[0].decision.kind).toBe("skipped");
  expect(db.query("SELECT count(*) AS n FROM auth_credential_blocks").get()).toEqual({ n: 1 });
  expect(db.query("SELECT disabled_cause FROM auth_credentials WHERE id = 1").get()).toEqual({ disabled_cause: null });
}));

test("chat and spark meter scopes use report evidence regardless of provider name", () => fixture((db, file, now) => {
  row(db, 1, "vendor-alpha", "alpha@example.test", now);
  row(db, 2, "vendor-beta", "beta@example.test", now);
  block(db, 1, "vendor-alpha", "chat", now);
  block(db, 2, "vendor-beta", "spark", now);
  const reports: Report[] = [
    { provider: "vendor-alpha", fetchedAt: now, metadata: { email: "alpha@example.test", meterStates: { chat: { allowed: true, limitReached: false } } },
      limits: [{ id: "vendor-alpha:primary", scope: { provider: "vendor-alpha" }, amount: { usedFraction: 0.2 }, status: "ok" }] },
    { provider: "vendor-beta", fetchedAt: now, metadata: { email: "beta@example.test", meterStates: { spark: { allowed: true, limitReached: false } } },
      limits: [{ id: "vendor-beta:spark:weekly", scope: { provider: "vendor-beta", tier: "spark" }, amount: { usedFraction: 0.1 }, status: "ok" }] },
  ];
  expect(reconcileDb(file, reports, 0.05, now).map(result => result.decision.kind)).toEqual(["corrected", "corrected"]);
  expect(db.query("SELECT count(*) AS n FROM auth_credential_blocks").get()).toEqual({ n: 0 });
}));
