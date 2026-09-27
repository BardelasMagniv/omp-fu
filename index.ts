/** /fu: reconcile only individually attributable, freshly healthy local credential blocks. */
import { existsSync } from "node:fs";
import { getAgentDbPath } from "@oh-my-pi/pi-utils";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { reconcileDb, type Report } from "./fu-policy.ts";

async function reserveFrom(args: string): Promise<number | undefined> {
  const tokens = args.trim().split(/\s+/).filter(Boolean);
  if (tokens.length && (tokens.length !== 2 || tokens[0] !== "--reserve")) return;
  const override = tokens.length ? tokens[1] : process.env.OMP_FU_RESERVE_FRACTION;
  if (override !== undefined) {
    if (!/^(?:0(?:\.\d+)?|1(?:\.0+)?)$/.test(override)) return;
    return Number(override);
  }
  // The installed OMP binary exposes the effective profile/project value via its CLI.
  // Older and newer extension SDKs expose different in-process settings facades.
  const child = Bun.spawn([process.execPath, "config", "get", "retry.usageReservePct"], {
    cwd: process.cwd(), env: process.env, stdout: "pipe", stderr: "pipe",
  });
  const [stdout, , exit] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  const text = stdout.trim();
  if (exit !== 0 || !/^(?:\d+)(?:\.\d+)?$/.test(text)) return;
  const percent = Number(text);
  return Number.isFinite(percent) && percent >= 0 && percent <= 100 ? percent / 100 : undefined;
}
function output(ctx: { hasUI: boolean; ui: { notify(message: string, level?: "info" | "warning" | "error"): void } }, text: string): void {
  if (ctx.hasUI) ctx.ui.notify(text, "info");
  else process.stdout.write(text + "\n");
}

export default function fu(pi: ExtensionAPI): void {
  pi.registerCommand("fu", {
    description: "Reconcile stale local credential blocks only when fresh account-scoped usage proves quota available (/fu [--reserve 0..1])",
    handler: async (args, ctx) => {
      const reserve = await reserveFrom(args);
      if (reserve === undefined) {
        output(ctx, "Usage: /fu [--reserve 0..1]. Requires an active OMP usage reserve or OMP_FU_RESERVE_FRACTION.");
        return;
      }
      const storage = ctx.modelRegistry?.authStorage;
      if (!storage || typeof storage.usage?.invalidate !== "function" || typeof storage.usage?.reports !== "function" ||
          typeof storage.credentials?.snapshot !== "function" || typeof storage.credentials?.list !== "function") {
        output(ctx, "/fu skipped: local usage/auth APIs unavailable; no blocks changed.");
        return;
      }
      const dbPath = getAgentDbPath();
      if (!existsSync(dbPath)) { output(ctx, "/fu skipped: local agent database missing; no blocks changed."); return; }
      try {
        // A remote auth broker can return reports for accounts absent from the local DB.
        // Never mutate the local mirror when the active registry is not this DB.
        const { Database } = await import("bun:sqlite");
        const localRows = (): Array<{ id: number; provider: string; credential_type: string; data: string }> => {
          const db = new Database(dbPath, { readonly: true, strict: true });
          try { return db.query("SELECT id, provider, credential_type, data FROM auth_credentials WHERE disabled_cause IS NULL").all() as Array<{ id: number; provider: string; credential_type: string; data: string }>; }
          finally { db.close(); }
        };
        const isLocal = () => {
          const local = localRows();
          const active = storage.credentials.snapshot().credentials as Array<{ id: number; provider: string; credential: { type: string; access?: string; key?: string } }>;
          return active.length === local.length &&
            !storage.credentials.list().some(entry => entry.credential.type === "oauth" && entry.credential.refresh === "__remote__") &&
            active.every(entry => local.some(row => {
              if (row.id !== entry.id || row.provider !== entry.provider || row.credential_type !== entry.credential.type) return false;
              const parsed: unknown = JSON.parse(row.data);
              if (!parsed || typeof parsed !== "object") return false;
              const data = parsed as Record<string, unknown>;
              return entry.credential.type === "oauth" ? data.access === entry.credential.access : data.key === entry.credential.key;
            }));
        };
        if (!isLocal()) {
          output(ctx, "/fu skipped: active auth store differs from local SQLite (remote broker or stale snapshot); no blocks changed.");
          return;
        }
        await storage.usage.invalidate();
        const reports = await storage.usage.reports({ baseUrlResolver: provider => ctx.modelRegistry.getProviderBaseUrl(provider) });
        if (!Array.isArray(reports)) { output(ctx, "/fu skipped: no live usage API response; OMP may have reconciled blocks during refresh."); return; }
        if (!reports.every(report => report && typeof report.provider === "string" &&
            Number.isFinite(report.fetchedAt) && Array.isArray(report.limits) &&
            report.limits.every(limit => limit && typeof limit.id === "string" &&
              limit.scope && typeof limit.scope.provider === "string" && limit.amount &&
              typeof limit.amount === "object"))) {
          output(ctx, "/fu skipped: malformed usage report; OMP may have reconciled blocks during refresh.");
          return;
        }
        if (!isLocal()) {
          output(ctx, "/fu skipped: active auth store changed while fetching usage; OMP may have reconciled blocks during refresh.");
          return;
        }
        const outcomes = reconcileDb(dbPath, reports as Report[], reserve);
        const totals = { corrected: 0, unchanged: 0, skipped: 0 };
        const lines: string[] = [];
        for (const { block, decision } of outcomes) {
          totals[decision.kind]++;
          lines.push(`  ${decision.kind}: ${block.provider_key} #${block.credential_id} [${block.block_scope || "unscoped"}] — ${decision.reason}`);
        }
        output(ctx, [`/fu: corrected ${totals.corrected}, unchanged ${totals.unchanged}, skipped ${totals.skipped} (reserve ${reserve}).`,
          ...lines, ...(outcomes.length ? [] : ["  No active local blocks to reconcile."])].join("\n"));
      } catch (error) {
        // Never echo error text: provider/SQLite exceptions may include credential data.
        pi.logger.warn("/fu failed", { error: error instanceof Error ? error.name : "unknown" });
        output(ctx, "/fu stopped: usage fetch or local database failed; OMP may have reconciled blocks during refresh.");
      }
    },
  });
}
