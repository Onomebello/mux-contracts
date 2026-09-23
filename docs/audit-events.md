# Mux Protocol — Audit Log Events

**Version:** 0.1.0  
**Status:** Living document — update whenever a new event is added or an existing one changes.

> **Conventions:** Topic layout, naming rules, and TypeScript filter notes are defined in
> [event-topic-conventions.md](event-topic-conventions.md). This file is the per-contract catalog.

---

## Overview

Every state-mutating operation in Mux contracts emits a Soroban event via `env.events().publish(topics, data)`.  
Events are indexed on-chain and can be streamed from any Soroban RPC node using the `getEvents` method.

### Topic structure

All events use a two-element topic vector:

```
topics[0]  contract_tag  Symbol  e.g. "mux_acct", "mux_perm", "mux_bat"
topics[1]  action        Symbol  e.g. "init", "dlg_set", "role_grt"
```

The `data` field carries action-specific payload encoded as a Soroban `Val`.

See [event-topic-conventions.md](event-topic-conventions.md) for naming rules, the full tag table, and RPC filter examples.

---

## Audit correlation fields

Every audit event carries a set of **correlation fields** so that off-chain
consumers can group, order, and verify events without trusting the indexer.
These fields are part of the event contract and are covered by the invariants
below.

### Correlation fields

| Field | Type | Meaning |
|---|---|---|
| `correlation_id` | `BytesN<32>` | Stable identifier for the logical operation. Deterministic per `(contract_tag, action, caller, nonce)`; identical across every event emitted by the same top-level call. |
| `sequence` | `u64` | Monotonic per-contract counter, incremented once per emitted event. Never reused, never decreases. |
| `parent_id` | `Option<BytesN<32>>` | `correlation_id` of the enclosing call when this event is emitted from a nested/child invocation; `None` for top-level events. |
| `prev_hash` | `BytesN<32>` | Hash of the previous event's `(correlation_id, sequence, action, data)` tuple for this contract. `None`-equivalent (all-zero) for the first event. |

### Invariants

1. **Stable correlation IDs.** For a given top-level call, `correlation_id` is
   computed once and reused verbatim by every event the call emits. It is a
   pure function of `(contract_tag, action, caller, nonce)` and MUST NOT depend
   on wall-clock time, ledger sequence, or any value that can differ between
   simulation and execution.
2. **Monotonic sequencing.** `sequence` is a per-contract `u64` stored in
   instance storage, incremented exactly once per emitted event. It is strictly
   increasing and gap-free within a contract; a replayed or failed call MUST
   NOT advance it.
3. **Tamper-evident linkage.** `prev_hash` chains each event to its predecessor
   via `SHA-256(correlation_id || sequence || action || data)`. A consumer that
   has any trusted event can recompute the chain forward and detect insertion,
   reordering, or deletion.
4. **Fail-closed emission.** If any correlation field cannot be computed (e.g.
   storage read fails), the emitting call MUST abort rather than publish an
   event with a missing or defaulted field.

### Idempotency

Audit submissions are idempotent on `correlation_id`. A repeated submission
with the same `correlation_id` is a no-op: it MUST NOT emit a second event and
MUST NOT advance `sequence`. Concurrent submissions are serialized by the
per-contract `sequence` counter; the loser of the race observes the winner's
`correlation_id` and returns the existing event reference instead of writing.

### Failure modes

- **Dependency outage (RPC/DB/Horizon).** Writes fail closed: if the audit
  sink is unreachable, the state-mutating call reverts. Reads may degrade to
  cached data but MUST surface a stale marker.
- **Auth expiry / wrong role / revoked delegate.** Authorization is checked
  before any correlation field is computed; denied calls emit no event and do
  not advance `sequence`.
- **Adversarial input.** Oversized batches are rejected before emission;
  spoofed `correlation_id` values that do not match the recomputed hash are
  rejected. Rate limits apply per caller.

### Authorization

Emitting audit events is a privileged surface. Deny-by-default: only the
contract owner, an unexpired delegate with the `audit` permission, or a
caller presenting a valid API key/JWT bound to the contract may trigger
emission. Guardians may pause emission but cannot forge events.

### Observability

Emission failures log a stable error code (`AUDIT_CORRELATION_MISSING`,
`AUDIT_SEQUENCE_REGRESSION`, `AUDIT_CHAIN_MISMATCH`) with the offending
`correlation_id` and `sequence`. Logs MUST NOT contain raw key material,
JWTs, or webhook secrets — redact before logging.

---

## mux-account events

Contract tag: `mux_acct`

| Action | Trigger | Data payload |
|---|---|---|
| `init` | `initialize` succeeds | `owner: Address` |
| `unpaused` | `unpause` succeeds | `()` |
| `dlg_set` | `set_delegate` succeeds | `(delegate: Address, expires_at: u64, can_spend: bool)`; `expires_at` is a Unix timestamp |
| `dlg_rm` | `remove_delegate` succeeds | `delegate: Address` |
| `lmt_set` | `set_spend_limit` succeeds | `(asset: Address, amount: i128, period_ledgers: u32)` |
| `debited` | `debit_spend` succeeds | `(asset: Address, spend: i128)` |
| `ses_exe` | `execute_with_session` succeeds | `SessionExecutedEvent { session_key: Address, payload_len: u32 }` |
| `meta_set` | `set_metadata` succeeds | `name: String` (from the `RegistryMeta` argument) |

> `register_session_key` and `revoke_session_key` do not currently emit
> dedicated audit events.

---

## mux-account-factory events

Contract tag: `mux_fac`

| Action | Trigger | Data payload |
|---|---|---|
| `deployed` | `deploy_account` or `deploy_account_with_metadata` succeeds | `(owner: Address, account_address: Address)` |
| `meta_set` | `deploy_account_with_metadata` succeeds | `(owner: Address, account_address: Address, version: String)` |

Event ordering within a single `deploy_account_with_metadata` call:
1. `deployed` — always emitted first
2. `meta_set` — always emitted second, in the same transaction

**No-event paths** — the following entrypoints are read-only or validation-only
and **must never emit events**:

| Entrypoint | Reason |
|---|---|
| `get_accounts` | Pure read — no state mutation |
| `account_count` | Pure read — no state mutation |
| `get_account_metadata` | Pure read — no state mutation |
| `simulate_deploy` | Dry-run validation; no storage written |
| `simulate_deploy_with_metadata` | Dry-run validation; no storage written |
| `max_accounts_per_owner` | Returns a constant; no storage touched |

Auth failures (`owner.require_auth()` rejected) and all `Result::Err` return
paths (`InvalidAccount`, `TooManyAccounts`, `MetadataTooLarge`) also emit zero
events — the emit call is only reached after every validation step passes.

**TypeScript — filtering factory events:**

```ts
import {
  FACTORY_CONTRACT_TAG,
  FACTORY_EVENT_TOPICS,
  parseFactoryEvent,
  type FactoryEvent,
} from "@mux-protocol/contracts";

const rawEvents = await server.getEvents({
  startLedger,
  filters: [{
    type: "contract",
    contractIds: [FACTORY_CONTRACT_ID],
    topics: [[FACTORY_CONTRACT_TAG]],          // filter by contract tag only
  }],
});

const events: FactoryEvent[] = rawEvents.records
  .map(parseFactoryEvent)
  .filter((e): e is FactoryEvent => e !== null);

// Narrow to just deploys:
const deploys = events.filter(e => e.action === "deployed");
// Narrow to just metadata updates:
const metaUpdates = events.filter(e => e.action === "meta_set");
```

---

## mux-permissions events

Contract tag: `mux_perm`

| Action | Trigger | Data payload |
|---|---|---|
| `init` | `initialize` succeeds | `admin: Address` |
| `role_crt` | `create_role` succeeds | `role: Symbol` |
| `role_grt` | `grant_role` succeeds | `(account: Address, role: Symbol)` |
| `role_rev` | `revoke_role` succeeds | `(account: Address, role: Symbol)` |
| `adm_thr` | `set_admin_threshold` succeeds | `threshold: u32` |
| `adm_prp` | `propose_admin` adds a new candidate | `new_admin: Address` |
| `adm_apr` | `approve_admin` records an approval (threshold not yet reached) | `(approver: Address, new_admin: Address)` |
| `adm_prm` | `approve_admin` promotes a candidate (threshold reached) | `new_admin: Address` |
| `perm_ok` | `has_permission` returns `true` | `(account: Address, permission: Symbol)` |
| `perm_den` | `has_permission` returns `false` | `(account: Address, permission: Symbol)` |
| `meta_set` | `set_metadata` succeeds | `name: String` (from the `RegistryMeta` argument) |

> Unlike every other event in this table, `perm_ok`/`perm_den` are emitted by
> a read-only query (`has_permission`), not a state-mutating call — every
> permission check is itself audit-logged.

> `upgrade` emits no event — instance storage (including this event log's
> continuity) survives the WASM replace, so there is nothing new to log; the
> upload/invoke transaction itself is the audit record. Follows the same
> convention as `mux-policy`'s `upgrade`.

---

## mux-delegation events

Contract tag: `mux_dlg`

| Action | Trigger | Data payload |
|---|---|---|
| `init` | `initialize` succeeds | `admin: Address` |
| `dlg_grant` | `grant_delegate` succeeds | `(owner: Address, delegate: Address)` |
| `dlg_rev` | `revoke_delegate` succeeds | `(owner: Address, delegate: Address)` |
| `dlg_link` | `link_contract_id` succeeds | `(admin: Address, contract_id: Address)` |

Events are emitted only on success. Failed calls (auth failure, empty
permissions, cap exceeded, already-linked contract ID) emit no events.
permissions, cap exceeded) emit no events. `upgrade` emits no event — see
the note under mux-permissions above; the same convention applies here.

> **Note:** `initialize` is optional and only establishes the `upgrade()`
> admin — it is independent of the `admin` parameter accepted by
> `link_contract_id`, which authorises itself and is not checked against the
> stored admin. See [delegation-upgrade.md](delegation-upgrade.md).

> **Note:** The event data carries only `(owner, delegate)`. The full
> permission list granted/revoked is **not** included in the event — retrieve
> it via `get_delegate_permissions` if needed.

**TypeScript — subscribing and parsing delegation events:**

```ts
import {
  DELEGATION_CONTRACT_TAG,
  DELEGATION_GRANT_ACTION,
  DELEGATION_REVOKE_ACTION,
  parseDelegationEvent,
  type DelegationEvent,
} from "@mux-protocol/contracts";

const rawEvents = await server.getEvents({
  startLedger,
  filters: [{
    type: "contract",
    contractIds: [DELEGATION_CONTRACT_ID],
    topics: [[DELEGATION_CONTRACT_TAG]],   // all mux_dlg events
  }],
});

const events: DelegationEvent[] = rawEvents.records
  .map(parseDelegationEvent)
  .filter((e): e is DelegationEvent => e !== null);

// Narrow to grants only:
const grants = events.filter(e => e.action === DELEGATION_GRANT_ACTION);
// Narrow to revokes only:
const revokes = events.filter(e => e.action === DELEGATION_REVOKE_ACTION);
```

See [`docs/delegation-permission-model.md`](delegation-permission-model.md)
for the full permission model and security notes.

---

## mux-batcher events

Contract tag: `mux_bat`

| Action | Trigger | Data payload |
|---|---|---|
| `bat_start` | `execute_batch` begins, before any operation runs | `(caller: Address, op_count: u32)` |
| `executed` | `execute_batch` completes (success or partial failure) | `(caller: Address, success_count: u32, failure_count: u32)` |
| `bat_ok` | `execute_batch` completes with zero failures | `(caller: Address, success_count: u32)` |
| `bat_abort` | A `require_success=true` operation fails | `caller: Address` |
| `sim_done` | `si

/* … truncated 5167 chars — edit only what you need near the top … */
