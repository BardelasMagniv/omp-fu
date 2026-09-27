# omp-fu

A manual OMP extension that refreshes provider usage and clears **only provably stale local credential cooldowns**. It does not patch OMP source or grant additional provider quota.

## Install

Clone into the active OMP profile's `extensions` directory (default profile shown):

```sh
git clone https://github.com/BardelasMagniv/omp-fu.git "$HOME/.omp/agent/extensions/fu"
```

Restart OMP, then enter `/fu`. OMP loads `index.ts` automatically; the other TypeScript files are support code and tests. For a named profile, use that profile's `agent/extensions/fu` directory instead. Update later with `git -C "$HOME/.omp/agent/extensions/fu" pull`, then restart OMP.

## What `/fu` does

- Refreshes usage for all accounts/providers OMP can report. Matches each persisted local block to exactly one enabled OAuth account and its fresh usage report.
- Deletes only an exact block contradicted by fresh, matching quota data above the reserve. Each deletion is guarded by a database transaction; changed or ambiguous rows are skipped.
- Prints corrected, unchanged, and skipped blocks with reasons, without printing credentials or account email.

The reserve comes from the active profile/project `retry.usageReservePct` through OMP's config command. `/fu --reserve 0.10` requires over 10% remaining; `OMP_FU_RESERVE_FRACTION` provides a default override (fractions 0–1). If launching OMP with a one-off `--config` overlay, specify `--reserve` explicitly: the child config command does not inherit that overlay.

## Safety and limitations

Unreported or ambiguous quotas, expired/stale reports, unknown or exhausted meters, disabled accounts, API-key credentials without a safe account match, and remote auth brokers are never cleared by this extension. Scope-specific blocks require a matching meter; a `shared` compatibility mirror is never deleted directly. A successful provider usage report is not proof against every model-specific limit: a provider can reject the next request and OMP can block it again.

OMP's own usage refresh may independently reconcile blocks before `/fu` counts its corrections. An existing session may stay on its fallback or retain an in-memory backoff; reselect your model or start a new session after a correction. The files survive normal OMP binary updates, but future OMP API/schema changes may require updating this extension; it fails closed when its required APIs are unavailable.

## Verify

From this directory, run `bun test fu.test.ts` for isolated SQLite behavior tests. To check command registration without touching real account blocks, use an empty throwaway profile:

```sh
omp --no-extensions -e ./index.ts --profile fu-smoke -p --no-session --no-title "/fu"
```

Do not seed or alter real credential blocks merely to test this command.

## License

MIT — see [LICENSE](LICENSE).
