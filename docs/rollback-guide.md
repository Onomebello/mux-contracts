# Partial Crate Rollback Guide

This guide is the canonical reference for **partial crate rollback** in `mux-contracts`.
It defines what may be rolled back, what must remain the source of truth, and how
rollback operations fail closed. It is written for Stellar Wave contributors and
operators touching AA/wallet/payment paths.

> Scope: partial rollback only. Full-chain reorgs, irreversible mainnet ops, and
> unrelated refactors are out of scope.

## 1. Invariants

These invariants MUST hold for every partial rollback. A rollback that cannot
satisfy all of them MUST be rejected (fail closed).

1. **Server/contract is the source of truth.** Spends, recovery, and admin state
   are authoritative on-chain / server-side. Client-supplied rollback intent is a
   *request*, never a fact.
2. **Partial only.** A rollback may revert a bounded, identified set of crate
   state (e.g. a single crate version's storage keys or a single operation batch).
   It MUST NOT revert unrelated crates, global config, or ownership.
3. **Monotonic safety.** Rollback MUST NOT resurrect already-finalized spends or
   re-enable a revoked delegate/guardian.
4. **Idempotent.** Replaying the same rollback request (same correlation id) MUST
   be a no-op after the first successful application.
5. **Fail closed on writes.** If the RPC/DB/Horizon dependency is unavailable or
   returns an ambiguous result, the rollback MUST abort without mutating state.
6. **Deny by default.** Any new privileged rollback surface is unauthorized until
   an explicit role grants it.

## 2. Typed APIs and entrypoints

Rollback entrypoints are typed and return stable error codes. Correlation ids are
required so operators can trace a rollback across logs and metrics.

```ts
// bindings/rollback.ts (shape reference)
export interface PartialRollbackRequest {
  /** Bounded target: crate id + version range to revert. */
  crateId: string;
  fromVersion: string;
  toVersion: string;
  /** Idempotency key; reused on retry. */
  correlationId: string;
  /** Actor identity resolved server-side; never trusted from the body. */
  actor: RollbackActor;
}

export type RollbackActor =
  | { kind: "owner" }
  | { kind: "delegate"; delegateId: string }
  | { kind: "guardian"; guardianId: string };

export interface PartialRollbackResult {
  correlationId: string;
  status: "applied" | "noop" | "rejected";
  errorCode?: RollbackErrorCode;
}
```

### Stable error codes

| Code | Meaning |
|------|---------|
| `RB_ROLLBACK_UNAUTHORIZED` | Actor lacks the required role for this crate. |
| `RB_ROLLBACK_OUT_OF_SCOPE` | Target is not a bounded partial rollback. |
| `RB_ROLLBACK_REPLAYED` | Correlation id already applied (idempotent no-op). |
| `RB_ROLLBACK_DEPENDENCY_DOWN` | RPC/DB/Horizon unavailable; aborted, no writes. |
| `RB_ROLLBACK_CONFLICT` | Target state changed since request; re-read and retry. |
| `RB_ROLLBACK_INVALID_INPUT` | Malformed or oversized request. |

## 3. Authorization

Every rollback entrypoint is authorized server-side. Clients cannot bypass policy
by supplying an actor in the request body.

- **owner** — may roll back any crate they own.
- **delegate** — may roll back only crates explicitly delegated to them; a revoked
  delegate is rejected (`RB_ROLLBACK_UNAUTHORIZED`).
- **guardian** — may roll back only within the guardian's recovery scope.
- **API-key / JWT** — must be valid, unexpired, and carry the rollback scope; an
  expired or wrong-role token is rejected.

Deny by default: a new rollback surface ships disabled until a role is granted.

## 4. Observability (ops-safe)

Rollback paths emit actionable errors and metrics **without leaking secrets**.

Metrics:

- `rollback_requests_total{status,error_code}`
- `rollback_applied_total{crate_id}`
- `rollback_dependency_failures_total{dependency}`

Logs MUST redact:

- private keys / seed phrases / raw key material
- JWTs and API keys (log only a short hash or last-4 fingerprint)
- webhook secrets

Log the `correlationId`, `crateId`, `fromVersion`/`toVersion`, resolved role, and
`errorCode`. Never log request bodies verbatim.

## 5. Failure modes

| Failure | Required behavior |
|---------|-------------------|
| Concurrent / replayed request | Idempotent via `correlationId`; second call returns `noop`. |
| RPC/DB/Horizon outage | Abort with `RB_ROLLBACK_DEPENDENCY_DOWN`; no writes. |
| Auth expiry / wrong role / revoked delegate | Reject with `RB_ROLLBACK_UNAUTHORIZED`. |
| Oversized batch / griefing / spoofed webhook | Reject with `RB_ROLLBACK_INVALID_INPUT`; rate-limit entrypoint. |
| Testnet vs mainnet misconfig | Refuse to run; require explicit network passphrase match. |

## 6. Rollback and flag strategy

- Ship money-path or mainnet-affecting rollback changes behind a feature flag /
  kill-switch, default off.
- Document the flag name and the exact steps to disable it in the PR description.
- A rollback of a rollback is itself a partial rollback and follows this guide.

## 7. Related docs

- [SECURITY.md](../SECURITY.md) — reporting and threat model.
- [docs/threat-model.md](threat-model.md) — trust boundaries.
- [docs/access-control-checklist.md](access-control-checklist.md) — authz review.
