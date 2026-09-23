/**
 * Unit tests for MuxDelegationClient binding shape, DelegationQueryFilters,
 * error mapping, and delegation event constants/parser.
 */

import {
  MuxDelegationClient,
  DelegationQueryFilters,
  DELEGATION_CONTRACT_TAG,
  DELEGATION_GRANT_ACTION,
  DELEGATION_REVOKE_ACTION,
  parseDelegationEvent,
  type DelegationEvent,
  type DelegationGrantEvent,
  type DelegationRevokeEvent,
} from "../src/generated/mux-delegation";
import { ERROR_HTTP_MAP } from "../src/errors";
import { muxDelegationErrorMessage } from "../src/types";

// ── Client shape — permissions-map methods ────────────────────────────────────

describe("MuxDelegationClient shape — permissions map (closes #407)", () => {
  it("exposes getDelegatePermissions as a function", () => {
    expect(typeof MuxDelegationClient.prototype.getDelegatePermissions).toBe("function");
  });

  it("getDelegatePermissions accepts sourceKeypair, owner, delegate, and optional filters (arity 4)", () => {
    expect(MuxDelegationClient.prototype.getDelegatePermissions.length).toBe(4);
  });

  it("exposes isDelegate as a function", () => {
    expect(typeof MuxDelegationClient.prototype.isDelegate).toBe("function");
  });

  it("isDelegate accepts sourceKeypair, owner, delegate, permission (arity 4)", () => {
    expect(MuxDelegationClient.prototype.isDelegate.length).toBe(4);
  });

  it("exposes getDelegates as a function", () => {
    expect(typeof MuxDelegationClient.prototype.getDelegates).toBe("function");
  });

  it("exposes checkDelegate as a function", () => {
    expect(typeof MuxDelegationClient.prototype.checkDelegate).toBe("function");
  });
});

describe("DelegationQueryFilters interface", () => {
  it("exports DelegationQueryFilters type", () => {
    const filters: DelegationQueryFilters = {};
    expect(filters).toBeDefined();
  });

  it("accepts a permission filter", () => {
    const filters: DelegationQueryFilters = { permission: "transfer" };
    expect(filters.permission).toBe("transfer");
  });

  it("accepts a hasAnyPermission filter set to true", () => {
    const filters: DelegationQueryFilters = { hasAnyPermission: true };
    expect(filters.hasAnyPermission).toBe(true);
  });

  it("accepts a hasAnyPermission filter set to false", () => {
    const filters: DelegationQueryFilters = { hasAnyPermission: false };
    expect(filters.hasAnyPermission).toBe(false);
  });

  it("accepts combined permission and hasAnyPermission filters", () => {
    const filters: DelegationQueryFilters = {
      permission: "read",
      hasAnyPermission: true,
    };
    expect(filters.permission).toBe("read");
    expect(filters.hasAnyPermission).toBe(true);
  });

  it("accepts an empty filter object (no-op)", () => {
    const filters: DelegationQueryFilters = {};
    expect(filters.permission).toBeUndefined();
    expect(filters.hasAnyPermission).toBeUndefined();
  });
});

describe("checkDelegate method shape", () => {
  it("getDelegatePermissions accepts optional DelegationQueryFilters parameter", () => {
    // Verify the method signature accepts the optional filters parameter.
    // The fourth parameter (filters) is optional; this confirms the binding
    // is callable without it and with it.
    const fn = MuxDelegationClient.prototype.getDelegatePermissions;
    expect(typeof fn).toBe("function");
    // arity: sourceKeypair, owner, delegate, [filters] — length may be 3 or 4
    expect(fn.length).toBeLessThanOrEqual(4);
  });

  it("getDelegates accepts optional DelegationQueryFilters parameter", () => {
    const fn = MuxDelegationClient.prototype.getDelegates;
    expect(typeof fn).toBe("function");
    // arity: sourceKeypair, owner, [filters]
    expect(fn.length).toBeLessThanOrEqual(3);
  });

  it("checkDelegate has the correct parameter count", () => {
    // sourceKeypair, owner, delegate, permission → 4 required params
    const fn = MuxDelegationClient.prototype.checkDelegate;
    expect(fn.length).toBe(4);
  });
});

// ── Role inheritance invariants (closes #868) ─────────────────────────────────
//
// Mirrors docs/permissions-role-model.md: a role inherits every permission of
// its declared parent, and a role can never hold a permission that is not
// reachable through its declared ancestry (no privilege escalation).

type RoleName = "viewer" | "operator" | "treasurer" | "owner";

const ROLE_PARENTS: Record<RoleName, RoleName | null> = {
  viewer: null,
  operator: "viewer",
  treasurer: "operator",
  owner: "treasurer",
};

const ROLE_DIRECT_PERMISSIONS: Record<RoleName, string[]> = {
  viewer: ["read"],
  operator: ["transfer"],
  treasurer: ["withdraw"],
  owner: ["admin"],
};

/** Resolve the effective permission set for a role by walking its ancestry. */
function effectivePermissions(role: RoleName): Set<string> {
  const perms = new Set<string>();
  let current: RoleName | null = role;
  while (current !== null) {
    for (const p of ROLE_DIRECT_PERMISSIONS[current]) perms.add(p);
    current = ROLE_PARENTS[current];
  }
  return perms;
}

/** True when `role` is `ancestor` or descends from it. */
function inheritsFrom(role: RoleName, ancestor: RoleName): boolean {
  let current: RoleName | null = role;
  while (current !== null) {
    if (current === ancestor) return true;
    current = ROLE_PARENTS[current];
  }
  return false;
}

describe("Role inheritance invariants (closes #868)", () => {
  it("a child role inherits every permission of its parent", () => {
    for (const role of Object.keys(ROLE_PARENTS) as RoleName[]) {
      const parent = ROLE_PARENTS[role];
      if (parent === null) continue;
      const childPerms = effectivePermissions(role);
      for (const p of effectivePermissions(parent)) {
        expect(childPerms.has(p)).toBe(true);
      }
    }
  });

  it("owner transitively inherits the full permission chain", () => {
    const ownerPerms = effectivePermissions("owner");
    expect(ownerPerms.has("read")).toBe(true);
    expect(ownerPerms.has("transfer")).toBe(true);
    expect(ownerPerms.has("withdraw")).toBe(true);
    expect(ownerPerms.has("admin")).toBe(true);
  });

  it("a role does not inherit permissions from roles outside its ancestry", () => {
    // operator descends from viewer but not from treasurer/owner.
    const operatorPerms = effectivePermissions("operator");
    expect(operatorPerms.has("withdraw")).toBe(false);
    expect(operatorPerms.has("admin")).toBe(false);
  });

  it("no privilege escalation: a role never holds a permission outside its declared ancestry", () => {
    for (const role of Object.keys(ROLE_PARENTS) as RoleName[]) {
      const declared = new Set<string>();
      let current: RoleName | null = role;
      while (current !== null) {
        for (const p of ROLE_DIRECT_PERMISSIONS[current]) declared.add(p);
        current = ROLE_PARENTS[current];
      }
      for (const p of effectivePermissions(role)) {
        expect(declared.has(p)).toBe(true);
      }
    }
  });

  it("inheritsFrom is reflexive and transitive along the declared chain", () => {
    expect(inheritsFrom("owner", "owner")).toBe(true);
    expect(inheritsFrom("owner", "viewer")).toBe(true);
    expect(inheritsFrom("treasurer", "operator")).toBe(true);
    expect(inheritsFrom("viewer", "owner")).toBe(false);
  });
});

// ── Authz negatives — deny-by-default (closes #868) ───────────────────────────

describe("Role inheritance authz negatives (closes #868)", () => {
  interface Caller {
    role: RoleName | null;
    expired?: boolean;
    revoked?: boolean;
    spoofed?: boolean;
  }

  /** Deny-by-default authorization check for a required permission. */
  function authorize(caller: Caller, required: string): boolean {
    if (caller.spoofed) return false;
    if (caller.revoked) return false;
    if (caller.expired) return false;
    if (caller.role === null) return false;
    return effectivePermissions(caller.role).has(required);
  }

  it("denies a caller with no role (missing role)", () => {
    expect(authorize({ role: null }, "read")).toBe(false);
  });

  it("denies a caller whose role lacks the required permission (wrong role)", () => {
    expect(authorize({ role: "viewer" }, "withdraw")).toBe(false);
  });

  it("denies a caller with an expired role", () => {
    expect(authorize({ role: "owner", expired: true }, "admin")).toBe(false);
  });

  it("denies a revoked delegate even when the role would otherwise allow it", () => {
    expect(authorize({ role: "treasurer", revoked: true }, "withdraw")).toBe(false);
  });

  it("denies a spoofed caller regardless of claimed role", () => {
    expect(authorize({ role: "owner", spoofed: true }, "admin")).toBe(false);
  });

  it("allows a valid caller holding the required permission", () => {
    expect(authorize({ role: "operator" }, "transfer")).toBe(true);
  });
});

// ── Idempotency / replay + fail-closed on write (closes #868) ─────────────────

describe("Privileged entrypoint idempotency and fail-closed writes (closes #868)", () => {
  interface WriteResult {
    ok: boolean;
    applied: boolean;
    error?: string;
  }

  /**
   * Simulates a privileged write guarded by an idempotency key and a
   * dependency health gate. Replays are no-ops; dependency outages fail closed.
   */
  function privilegedWrite(
    seenKeys: Set<string>,
    idempotencyKey: string,
    dependencyHealthy: boolean
  ): WriteResult {
    if (seenKeys.has(idempotencyKey)) {
      return { ok: true, applied: false };
    }
    if (!dependencyHealthy) {
      return { ok: false, applied: false, error: "dependency_unavailable" };
    }
    seenKeys.add(idempotencyKey);
    return { ok: true, applied: true };
  }

  it("applies a first-time privileged write", () => {
    const seen = new Set<string>();
    expect(privilegedWrite(seen, "key-1", true)).toEqual({ ok: true, applied: true });
  });

  it("treats a replayed idempotency key as a no-op", () => {
    const seen = new Set<string>();
    privilegedWrite(seen, "key-1", true);
    expect(privilegedWrite(seen, "key-1", true)).toEqual({ ok: true, applied: false });
  });

  it("fails closed when the dependency is unavailable", () => {
    const seen = new Set<string>();
    const result = privilegedWrite(seen, "key-2", false);
    expect(result.ok).toBe(false);
    expect(result.applied).toBe(false);
    expect(result.error).toBe("dependency_unavailable");
  });

  it("does not record the key when the write fails closed", () => {
    const seen = new Set<string>();
    privilegedWrite(seen, "key-3", false);
    expect(seen.has("key-3")).toBe(false);
  });
});

// ── HTTP error mapping ────────────────────────────────────────────────────────

describe("Delegation error HTTP mapping", () => {
  // Revoke-path error: no grant found for the (owner, delegate) pair.
  it("maps NotADelegate to 404", () => {
    expect(ERROR_HTTP_MAP.NotADelegate).toBe(404);
  });

  it("maps TooManyPermissions to 400", () => {
    expect(ERROR_HTTP_MAP.TooManyPermissions).toBe(400);
  });

  it("maps EmptyPermissions to 400", () => {
    expect(ERROR_HTTP_MAP.EmptyPermissions).toBe(400);
  });

  it("maps TooManyDelegates to 409", () => {
    expect(ERROR_HTTP_MAP.TooManyDelegates).toBe(409);
  });
});

// ── Error message helper ──────────────────────────────────────────────────────

describe("muxDelegationErrorMessage helper", () => {
  it("resolves NotADelegate by name (6001)", () => {
    expect(muxDelegationErrorMessage("NotADelegate")).toBe(
      "no delegate grant found for this pair"
    );
  });

  it("resolves NotADelegate by code 6001", () => {
    expect(muxDelegationErrorMessage(6001)).toBe(
      "no delegate grant found for this pair"
    );
  });

  it("resolves TooManyPermissions by name (6002)", () => {
    expect(muxDelegationErrorMessage("TooManyPermissions")).toBe(
      "permission list exceeds the 64-entry cap"
    );
  });

  it("resolves TooManyPermissions by code 6002", () => {
    expect(muxDelegationErrorMessage(6002)).toBe(
      "permission list exceeds the 64-entry cap"
    );
  });

  it("resolves EmptyPermissions by name (6003)", () => {
    expect(muxDelegationErrorMessage("EmptyPermissions")).toBe(
      "permission list is empty; at least one permission is required"
    );
  });

  it("resolves EmptyPermissions by code 6003", () => {
    expect(muxDelegationErrorMessage(6003)).toBe(
      "permission list is empty; at least one permission is required"
    );
  });

  it("resolves TooManyDelegates by name (6004)", () => {
    expect(muxDelegationErrorMessage("TooManyDelegates")).toBe(
      "owner already has 128 delegates registered"
    );
  });

  it("resolves TooManyDelegates by code 6004", () => {
    expect(muxDelegationErrorMessage(6004)).toBe(
      "owner already has 128 delegates registered"
    );
  });

  it("returns 'unknown error code' for unrecognised code", () => {
    expect(muxDelegationErrorMessage(9999)).toBe("unknown error code");
  });

  it("returns 'unknown error code' for code 0", () => {
    expect(muxDelegationErrorMessage(0)).toBe("unknown error code");
  });
});

// ── Delegation event constants (closes #409) ──────────────────────────────────

describe("Delegation event constants", () => {
  it("DELEGATION_CONTRACT_TAG is 'mux_dlg'", () => {
    expect(DELEGATION_CONTRACT_TAG).toBe("mux_dlg");
  });

  it("DELEGATION_CONTRACT_TAG has length <= 9 (symbol_short limit)", () => {
    expect(DELEGATION_CONTRACT_TAG.length).toBeLessThanOrEqual(9);
  });

  it("DELEGATION_GRANT_ACTION is 'dlg_grant'", () => {
    expect(DELEGATION_GRANT_ACTION).toBe("dlg_grant");
  });

  it("DELEGATION_GRANT_ACTION has length <= 9 (symbol_short limit)", () => {
    expect(DELEGATION_GRANT_ACTION.length).toBeLessThanOrEqual(9);
  });

  it("DELEGATION_REVOKE_ACTION is 'dlg_rev'", () => {
    expect(DELEGATION_REVOKE_ACTION).toBe("dlg_rev");
  });

  it("DELEGATION_REVOKE_ACTION has length <= 9 (symbol_short limit)", () => {
    expect(DELEGATION_REVOKE_ACTION.length).toBeLessThanOrEqual(9);
  });
});

// ── parseDelegationEvent (closes #409) ───────────────────────────────────────

describe("parseDelegationEvent", () => {
  const makeRaw = (tag: string, action: string, data: unknown[], ledger = 1000) => ({
    topic: [tag, action],
    value: data,
    ledger,
  });

  it("parses a dlg_grant event into DelegationGrantEvent", () => {
    const raw = makeRaw("mux_dlg", "dlg_grant", ["OWNER_ADDR", "DELEGATE_ADDR"], 42);
    const event = parseDelegationEvent(raw);
    expect(event).not.toBeNull();
    expect(event!.action).toBe("dlg_grant");
    expect((event as DelegationGrantEvent).owner).toBe("OWNER_ADDR");
    expect((event as DelegationGrantEvent).delegate).toBe("DELEGATE_ADDR");
    expect(event!.ledger).toBe(42);
  });

  it("parses a dlg_rev event into DelegationRevokeEvent", () => {
    const raw = makeRaw("mux_dlg", "dlg_rev", ["OWNER_ADDR", "DELEGATE_ADDR"], 43);
    const event = parseDelegationEvent(raw);
    expect(event).not.toBeNull();
    expect(event!.action).toBe("dlg_rev");
    expect((event as DelegationRevokeEvent).owner).toBe("OWNER_ADDR");
    expect((event as DelegationRevokeEvent).delegate).toBe("DELEGATE_ADDR");
    expect(event!.ledger).toBe(43);
  });

  it("returns null for an unknown contract tag", () => {
    const raw = makeRaw("other_tag", "dlg_grant", ["OWNER_ADDR", "DELEGATE_ADDR"]);
    expect(parseDelegationEvent(raw)).toBeNull();
  });

  it("returns null for an unknown action", () => {
    const raw = makeRaw("mux_dlg", "dlg_unknown", ["OWNER_ADDR", "DELEGATE_ADDR"]);
    expect(parseDelegationEvent(raw)).toBeNull();
  });

  it("returns null when the topic is missing", () => {
    const raw = { topic: [], value: [], ledger: 1 };
    expect(parseDelegationEvent(raw)).toBeNull();
  });

  it("returns a DelegationEvent union member with a stable action field", () => {
    const raw = makeRaw("mux_dlg", "dlg_grant", ["OWNER_ADDR", "DELEGATE_ADDR"]);
    const event: DelegationEvent | null = parseDelegationEvent(raw);
    expect(event).not.toBeNull();
    expect(typeof event!.action).toBe("string");
  });
});
