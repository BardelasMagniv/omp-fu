/** Fail-closed account attribution, quota evidence and guarded SQLite mutation. No token bytes leave callers. */
export interface CredentialRow {
  id: number; provider: string; credential_type: string; data: string;
  identity_key: string | null; disabled_cause: string | null; updated_at: number;
}
export interface BlockRow {
  credential_id: number; provider_key: string; block_scope: string;
  blocked_until_ms: number; updated_at: number;
}
export interface Limit {
  id: string; scope: { provider: string; accountId?: string; projectId?: string; orgId?: string; tier?: string; shared?: boolean };
  amount: { usedFraction?: number; remainingFraction?: number; used?: number; remaining?: number; limit?: number; unit?: string };
  status?: string; window?: { resetsAt?: number };
}
export interface Report { provider: string; fetchedAt: number; metadata?: Record<string, unknown>; limits: Limit[] }
export interface Decision { kind: "corrected" | "unchanged" | "skipped"; reason: string }
type Identity = { email?: string; accountId?: string; projectId?: string; orgId?: string };
const fields = ["email", "accountId", "projectId", "orgId"] as const;
function normalized(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim().toLowerCase() : undefined;
}
function identityValue(field: keyof Identity, value: unknown): string | undefined {
  if (typeof value !== "string" || !value.trim()) return;
  return field === "email" ? value.trim().toLowerCase() : value.trim();
}
function credentialIdentity(row: CredentialRow): Identity | undefined {
  try {
    const data: unknown = JSON.parse(row.data);
    if (!data || typeof data !== "object" || Array.isArray(data)) return;
    const record = data as Record<string, unknown>;
    const identity: Identity = {};
    for (const field of fields) identity[field] = identityValue(field, record[field]);
    const parts = row.identity_key?.split("|") ?? [];
    for (const part of parts) {
      const colon = part.indexOf(":");
      const name = part.slice(0, colon);
      const field = name === "account" ? "accountId" : name === "project" ? "projectId" : name === "org" ? "orgId" : name;
      if (colon < 1 || !fields.includes(field as typeof fields[number])) continue;
      const value = identityValue(field as keyof Identity, part.slice(colon + 1));
      if (identity[field as keyof Identity] && identity[field as keyof Identity] !== value) return;
      identity[field as keyof Identity] = value;
    }
    return identity;
  } catch { return; }
}
function reportIdentity(report: Report): Identity | undefined {
  const identity: Identity = {};
  const meta = report.metadata ?? {};
  for (const field of fields) identity[field] = identityValue(field, meta[field]);
  if (!identity.accountId) identity.accountId = identityValue("accountId", meta.account_id);
  for (const field of ["accountId", "projectId", "orgId"] as const) {
    const values = new Set(report.limits.map(limit => identityValue(field, limit.scope[field])).filter(Boolean));
    if (values.size > 1) return;
    const scoped = values.values().next().value as string | undefined;
    if (scoped && identity[field] && identity[field] !== scoped) return;
    identity[field] ??= scoped;
  }
  return identity;
}
function matches(a: Identity, b: Identity): boolean {
  if (a.orgId !== b.orgId && (a.orgId || b.orgId)) return false;
  let matched = false;
  for (const field of ["email", "accountId", "projectId"] as const) {
    if (a[field] && b[field]) {
      if (a[field] !== b[field]) return false;
      matched = true;
    }
  }
  // Project-only quota must not claim a user with an unmatched email/account identifier.
  if (!a.email && !b.email && !a.accountId && !b.accountId) return !!a.projectId && a.projectId === b.projectId && !a.orgId;
  return matched && (!!a.email && !!b.email || !!a.accountId && !!b.accountId);
}
export function matchReport(row: CredentialRow, rows: readonly CredentialRow[], reports: readonly Report[]): { report?: Report; reason?: string } {
  if (row.disabled_cause !== null) return { reason: "credential disabled" };
  if (row.credential_type !== "oauth") return { reason: "API-key quota identity unsupported" };
  const identity = credentialIdentity(row);
  if (!identity || ![identity.email, identity.accountId, identity.projectId].some(Boolean)) return { reason: "credential identity missing" };
  const candidates = reports.filter(report => report.provider === row.provider && (() => {
    const reportId = reportIdentity(report);
    return reportId !== undefined && matches(identity, reportId);
  })());
  if (candidates.length !== 1) return { reason: candidates.length ? "ambiguous reports" : "no matching usage report" };
  const report = candidates[0];
  const reportId = reportIdentity(report)!;
  const other = rows.filter(candidate => candidate.id !== row.id && candidate.provider === row.provider && candidate.disabled_cause === null && (() => {
    const id = credentialIdentity(candidate);
    return id !== undefined && matches(id, reportId);
  })());
  if (other.length) return { reason: "report matches multiple credentials" };
  return { report };
}
function scopeLimits(report: Report, block: BlockRow): Limit[] | undefined {
  const scope = block.block_scope;
  if (!scope) return report.limits;
  if (scope === "shared") return; // A legacy mirror DELETE cascades to unrelated meter rows.
  if (scope === "chat" || scope === "spark") {
    const state = (report.metadata?.meterStates as Record<string, { allowed?: boolean; limitReached?: boolean }> | undefined)?.[scope];
    if (state?.allowed !== true || state.limitReached !== false) return;
    return report.limits.filter(limit => {
      const meter = normalized(limit.scope.tier);
      const names = limit.id.split(":").slice(1).map(name => name.toLowerCase());
      return scope === "spark" ? meter === scope || names.includes(scope)
        : meter === scope || (!meter && (names[0] === "primary" || names[0] === "secondary"));
    });
  }
  if (scope.startsWith("tier:") && scope.length > 5) {
    const tier = scope.slice(5).toLowerCase();
    const scoped = report.limits.filter(limit => normalized(limit.scope.tier) === tier);
    return scoped.length ? report.limits.filter(limit => limit.scope.shared === true || scoped.includes(limit)) : [];
  }
  if (scope.startsWith("counter:") && scope.length > 8) {
    const counter = scope.slice(8).toLowerCase();
    return report.limits.filter(limit => limit.id.split(":")[1]?.toLowerCase() === counter);
  }
}
function healthy(limit: Limit, reserve: number, now: number, fetchedAt: number): boolean {
  if (limit.status !== undefined && limit.status !== "ok" && limit.status !== "warning") return false;
  if (limit.window?.resetsAt !== undefined && (!Number.isFinite(limit.window.resetsAt) || limit.window.resetsAt <= now)) return false;
  const amount = limit.amount;
  const available = [amount.remainingFraction,
    amount.remaining !== undefined && amount.limit !== undefined && amount.limit > 0 ? amount.remaining / amount.limit : undefined,
    amount.usedFraction !== undefined ? 1 - amount.usedFraction : undefined,
    amount.used !== undefined && amount.limit !== undefined && amount.limit > 0 ? 1 - amount.used / amount.limit : undefined,
  ].filter((value): value is number => typeof value === "number");
  return available.length > 0 && available.every(value => Number.isFinite(value) && value > reserve && value <= 1);
}
/** 2-minute freshness, 30-second propagation floor, and explicit positive headroom in every scoped window. */
export function decide(block: BlockRow, row: CredentialRow, report: Report, reserve: number, now: number): Decision {
  if (row.disabled_cause !== null || row.provider + ":" + row.credential_type !== block.provider_key || row.id !== block.credential_id)
    return { kind: "skipped", reason: "credential/block mismatch" };
  if (block.blocked_until_ms <= now) return { kind: "unchanged", reason: "block expired" };
  if (!Number.isFinite(report.fetchedAt) || report.fetchedAt > now + 5000 || now - report.fetchedAt > 120000 ||
      !Number.isFinite(block.updated_at) || report.fetchedAt < block.updated_at * 1000 + 30000)
    return { kind: "skipped", reason: "usage not fresh after block" };
  const limits = scopeLimits(report, block);
  if (!limits || limits.length === 0) return { kind: "skipped", reason: block.block_scope === "shared" ? "legacy shared mirror; unsafe cascade" : "missing or unsupported scoped meter" };
  if (limits.some(limit => limit.scope.provider !== report.provider || !healthy(limit, reserve, now, report.fetchedAt)))
    return { kind: "unchanged", reason: "quota unknown, exhausted, or below reserve" };
  return { kind: "corrected", reason: "fresh positive scoped quota" };
}


import { Database } from "bun:sqlite";
export interface Outcome { block: BlockRow; decision: Decision }
/** Never opens an absent database; only one qualifying block is deleted per immediate transaction. */
export function reconcileDb(dbPath: string, reports: readonly Report[], reserve: number, now = Date.now()): Outcome[] {
  if (!Number.isFinite(reserve) || reserve < 0 || reserve > 1) throw new RangeError("invalid reserve");
  const db = new Database(dbPath, { create: false, strict: true });
  try {
    const rows = db.query("SELECT id, provider, credential_type, data, identity_key, disabled_cause, updated_at FROM auth_credentials").all() as CredentialRow[];
    const blocks = db.query("SELECT credential_id, provider_key, block_scope, blocked_until_ms, updated_at FROM auth_credential_blocks WHERE blocked_until_ms > ? ORDER BY credential_id, provider_key, block_scope").all(now) as BlockRow[];
    const credential = db.query("SELECT id, provider, credential_type, data, identity_key, disabled_cause, updated_at FROM auth_credentials WHERE id = ?");
    const blockQuery = db.query("SELECT credential_id, provider_key, block_scope, blocked_until_ms, updated_at FROM auth_credential_blocks WHERE credential_id = ? AND provider_key = ? AND block_scope = ?");
    const siblingQuery = db.query("SELECT block_scope, blocked_until_ms, updated_at FROM auth_credential_blocks WHERE credential_id = ? AND provider_key = ? AND block_scope IN (?, ?) ORDER BY block_scope");
    const deletion = db.query(`DELETE FROM auth_credential_blocks WHERE credential_id = ? AND provider_key = ? AND block_scope = ? AND blocked_until_ms = ? AND updated_at = ?
      AND EXISTS (SELECT 1 FROM auth_credentials WHERE id = ? AND provider = ? AND credential_type = ?
      AND disabled_cause IS NULL AND updated_at = ? AND identity_key IS ? AND data = ?) RETURNING credential_id, provider_key, block_scope`);
    const output: Outcome[] = [];
    for (const block of blocks) {
      const row = rows.find(entry => entry.id === block.credential_id);
      if (!row) { output.push({ block, decision: { kind: "skipped", reason: "credential missing" } }); continue; }
      const matched = matchReport(row, rows, reports);
      if (!matched.report) { output.push({ block, decision: { kind: "skipped", reason: matched.reason ?? "no report" } }); continue; }
      const decision = decide(block, row, matched.report, reserve, now);
      if (decision.kind !== "corrected") { output.push({ block, decision }); continue; }
      let transactionStarted = false;
      try {
        db.run("BEGIN IMMEDIATE");
        transactionStarted = true;
        const current = credential.get(row.id) as CredentialRow | null;
        const currentBlock = blockQuery.get(block.credential_id, block.provider_key, block.block_scope) as BlockRow | null;
        if (!current || current.data !== row.data || current.identity_key !== row.identity_key ||
            current.updated_at !== row.updated_at || current.disabled_cause !== null || current.provider !== row.provider ||
            current.credential_type !== row.credential_type || !currentBlock ||
            currentBlock.updated_at !== block.updated_at || currentBlock.blocked_until_ms !== block.blocked_until_ms ||
            decide(block, current, matched.report, reserve, Date.now()).kind !== "corrected") {
          db.run("ROLLBACK");
          output.push({ block, decision: { kind: "skipped", reason: "credential/block changed or usage expired" } });
          continue;
        }
        // Codex meter DELETE triggers rebuild the shared compatibility mirror. Verify
        // the sibling meter is unchanged so a trigger update cannot silently clear it.
        const siblingBefore = block.block_scope === "chat" || block.block_scope === "spark"
          ? siblingQuery.all(block.credential_id, block.provider_key, "chat", "spark") as Array<{block_scope: string; blocked_until_ms: number; updated_at: number}> : [];
        const result = deletion.get(block.credential_id, block.provider_key, block.block_scope, block.blocked_until_ms,
          block.updated_at, row.id, row.provider, row.credential_type, row.updated_at, row.identity_key, row.data);
        if (!result) throw new Error("guarded deletion lost race");
        const settled = credential.get(row.id) as CredentialRow | null;
        if (!settled || settled.data !== row.data || settled.identity_key !== row.identity_key ||
            settled.disabled_cause !== null || settled.updated_at !== row.updated_at ||
            blockQuery.get(block.credential_id, block.provider_key, block.block_scope))
          throw new Error("credential changed during deletion or block was recreated");
        if (siblingBefore.length) {
          const siblingAfter = siblingQuery.all(block.credential_id, block.provider_key, "chat", "spark") as typeof siblingBefore;
          const siblings = (items: typeof siblingBefore) => JSON.stringify(items.filter(item => item.block_scope !== block.block_scope));
          if (siblings(siblingBefore) !== siblings(siblingAfter)) throw new Error("meter mirror changed an unrelated scope");
        }
        db.run("COMMIT");
        output.push({ block, decision });
      } catch {
        if (transactionStarted) { try { db.run("ROLLBACK"); } catch { /* A trigger may already have rolled back. */ } }
        output.push({ block, decision: { kind: "skipped", reason: "atomic guard/trigger rejected deletion" } });
      }
    }
    return output;
  } finally { db.close(); }
}
