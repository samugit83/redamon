---
name: Business Logic Flaws
description: Reference for business-logic testing covering invariant modeling, state-machine probing, refund / coupon / quota abuse, multi-tenant bleed, and saga / idempotency gaps.
---

# Business Logic Flaws

Reference for hunting domain-invariant violations: double-spend, single-use bypass, role retention after downgrade, cross-tenant bleed, refund / chargeback abuse, multi-step workflow skipping. Pull this in when the target has a non-trivial business model (e-commerce, fintech, SaaS, B2B) and you need a thinking framework rather than a payload list.

> Business-logic flaws are **invariant violations**. Every probe starts by naming an invariant the system claims to enforce, then constructing a request sequence that breaks it. Without an invariant, there is no finding.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Drive workflows in the UI | `execute_playwright` | Capture the request sequence per workflow. |
| Replay / mutate captured requests | `execute_curl` | Modify args, drop steps, replay stale steps. |
| Concurrency probes | `execute_code` | Pair with `/skill race_conditions` for parallel attacks. |
| Multi-account testing | `execute_curl` x N | Build a principal matrix (user A, user B, premium, admin). |
| Cross-channel parity | `execute_curl` + `/skill graphql` | REST / GraphQL / WebSocket may drift. |

## Step 1: model invariants

Pick the workflow. Before any payload, write down:

| Invariant class | Examples |
|---|---|
| Conservation of value | Sum of debits == sum of credits per ledger |
| Uniqueness | One coupon per user per cart; one vote per ballot |
| Monotonicity | A counter never decreases; an order status never moves backwards |
| Exclusivity | Only one active subscription per account |
| Bounding | `qty <= inventory_available`; `discount <= cart_subtotal` |
| Membership | `auth.uid in org_members` for every cross-tenant action |
| Sequence | `capture` requires a prior `auth`; `refund` requires a prior `capture` |

If you cannot articulate the invariant, you cannot find the flaw.

## Step 2: enumerate the state machine

For each workflow, record:

| For each transition | Capture |
|---|---|
| Endpoint | URL + method |
| Required pre-state | Server-derived flags / tokens (`stepToken`, `paymentIntentId`, `orderStatus`) |
| Required body fields | Server-trusted vs client-trusted |
| Side effects | Email, credit issuance, webhook, audit log |
| Post-state | New status / counter / role |
| Time bounds | TTL, grace periods, scheduling windows |

Example: e-commerce checkout

```
[cart] --add_item--> [cart]
[cart] --apply_coupon(C)--> [cart_with_discount]
[cart_with_discount] --create_order--> [pending_payment]
[pending_payment] --auth_payment--> [authorized]
[authorized] --capture--> [paid]
[paid] --ship--> [shipped]
[paid|shipped] --refund(amount)--> [refunded] (full) or [partially_refunded]
```

## Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive the state-machine probes from the recorded checkout / workflow sequence instead of rebuilding each request by hand. proxy_brain tools only see requests that went through the capture proxy, so run the workflow (via `execute_playwright` or the UI) through it first, then work from the captured transactions.

- `redamon.search({"host":"target.tld"})` and `redamon.sitemap()` recover the ordered transition set (add_item -> apply_coupon -> create_order -> auth -> capture) with methods and statuses, replacing manual re-capture for Step 2.
- Step-3 state-machine abuse is redamon.replay:
  - Skip / reorder: replay the `capture` transaction (`redamon.replay(<capture_txn>, {})`) without firing `auth` first.
  - Replay a stale step with mutated args: `redamon.replay(<order_txn>, {"body":"{\"price\":1,\"qty\":-1}"})` to test whether the server trusts client-supplied totals after approval.
  - Limit slicing / coupon stacking: re-fire a captured `apply_coupon` transaction repeatedly.
- Principal matrix: auth-swap a captured request with `redamon.replay(id, {"dropHeaders":["Cookie","Authorization"]})` or `{"headers":{"Authorization":"Bearer <userB>"}}` to run the same transition as user A, user B, premium, and admin.
- `redamon.diff(<pre_state_read>, <post_state_read>)` supplies the pre/post evidence the validation shape demands (counter moved, status advanced, refund doubled); `redamon.query({...})` reads the ledger / counter analytically over the traffic table to quantify the violation. `redamon.to_curl(id)` renders the minimal PoC request set.

Caveat: redamon.replay pins host/scheme/port to the origin, so cross-channel parity against a different host or the mobile back end still needs execute_curl; race amplification still runs through execute_code (see `/skill race_conditions`). redamon.fuzz only walks a query param, so mutate body / price positions by iterating redamon.replay.

## Step 3: probe matrix

### State-machine abuse

| Probe | Hypothesis |
|---|---|
| Skip a step (call `capture` before `auth`) | Server allows the transition |
| Repeat a step (call `apply_coupon` twice in different orders) | Discount stacks |
| Reorder steps (refund before capture) | Compensation without success path |
| Replay a stale step with mutated args (modify price after approval but before capture) | Server trusts client-supplied values |
| Split into sub-actions under a threshold | "Limit slicing" (10 transfers of 99 instead of one 1000) |

### Discount / coupon stacking

| Probe |
|---|
| Apply coupon A, then coupon B (server may not enforce mutual exclusivity) |
| Apply coupon, remove qualifying item, keep discount |
| Apply free-shipping coupon, then mutate cart to push under threshold |
| Apply coupon to one item; modify item to a more expensive one |
| Submit cart with negative-quantity item to absorb a positive discount |
| Same coupon in parallel (race) -> exceeds per-user limit |

### Numeric / currency

| Probe |
|---|
| Negative quantity / amount |
| Zero-price item with positive shipping |
| Float-vs-decimal rounding (`0.1 + 0.2 = 0.30000000000000004`) |
| Cross-currency: buy in JPY (no decimals), refund in USD (2 decimals) |
| Tax rounding per item vs per order (`0.005` rounded each way) |
| Scientific notation in numeric inputs (`1e-100`) |
| Integer-overflow on counters (`2^31`, `2^63`) |
| Free-shipping threshold edge: cart at exactly `49.99` vs `50.00` |

### Quota / inventory

| Probe |
|---|
| Reserve inventory, never complete -> stock leak |
| Pre-warm just before reset (T-1s, T+1s) to bypass daily / monthly counters |
| Cross-region writes when counters are sharded |
| Backorder enabled but front-end hides it -> oversell |
| Distributed counter eventual consistency window |

### Refund / chargeback

| Probe |
|---|
| Refund full amount via UI; refund residual via support endpoint |
| Refund partial amounts that sum > captured amount |
| Refund after digital goods downloaded / shipped (no post-consumption check) |
| Refund into a different payment method than captured |
| Chargeback dispute that auto-issues credit before legal flow |

### Role transitions

| Probe |
|---|
| Trial -> paid -> downgrade; verify premium features no longer accessible |
| Demote admin; replay an old admin token |
| Account deletion; verify residual sessions / refresh tokens dead |
| Suspend account; verify webhooks / scheduled jobs do not still mutate state |

### Idempotency abuse

(See also `/skill race_conditions` for the parallel angle.)

| Probe |
|---|
| Reuse another user's idempotency key (path-scoped only) |
| Reuse same key across path / method (scope binding) |
| Replay key after side effect committed but before response cached |
| Cron / queue retry without idempotent consumer -> duplicated emails / credits |

### Multi-tenant bleed

| Probe |
|---|
| Cross-tenant counters / credits updated without `org_id` in WHERE |
| Admin aggregate views actioning across tenants |
| Tenant header trust on internal services |
| Cross-tenant searches via lax `or=`/`ilike=` filters |

### Microservice boundary mismatches

| Probe |
|---|
| Service A validates totals; Service B trusts line items -> mutate between calls |
| Internal service trusts `X-User-Id` header from edge |
| Two-phase action where phase 1 commits without phase 2 (intermediate exploit window) |
| Worker re-execution on stored ID without re-validating ownership at execution time |

## Step 4: amplify

Once you have one invariant break, multiply impact:

| Multiplier | Technique |
|---|---|
| Race | Parallelize the broken transition |
| Tenants | Repeat across orgs |
| Schedules | Replay on cron windows |
| Channels | Reproduce via REST / GraphQL / WebSocket / mobile |
| Time | Replay across day / week / month boundaries (DST, billing cycles) |

## Cross-channel parity

Same logical action, different transports often drift. For every workflow, test:

| Channel | Path |
|---|---|
| REST | Standard JSON |
| GraphQL | Mutation with same arguments |
| WebSocket | Per-message handler |
| Background job | Trigger via supported endpoint, observe worker outcome |
| Webhook | If inbound webhooks are accepted, replay with attacker payload |
| Mobile | Often a richer feature set than web |

## Bypass techniques summary

- Content-type switching for parser differentials (`application/json` vs `text/plain` vs `multipart/form-data`).
- Method override (`X-HTTP-Method-Override`).
- Client-recomputed totals / discounts that the server accepts.
- Cache / gateway differentials that serve stale decisions.
- GraphQL alias batching: many state changes in one request.

## Validation shape

A clean business-logic finding includes:

1. The named invariant the system claims to enforce.
2. The exact request sequence (or single request) that breaks it.
3. Pre / post state evidence from authoritative sources (ledger, admin view, email).
4. The amount or count of the violation (`refunded $100 twice on a $100 charge`, `redeemed coupon 5 times when limit was 1`).
5. Reproduction recipe: minimum step set, exact accounts, exact timing.
6. Quantified impact: `unit_loss * feasible_repetition_rate = $X / hour`.

## False positives

- Behavior explicitly allowed by policy (documented promotional credits, goodwill refunds).
- Visual-only inconsistency with no durable state change.
- Admin operations that go through approval workflows (audit-logged + reviewed).
- One-time bonuses that documentation explicitly grants.

## Hand-off

```
Business logic + race            -> /skill race_conditions for the synchronization recipe
Business logic + IDOR             -> built-in / community IDOR skills
Business logic + CSRF amplifier   -> /skill csrf
Cross-tenant bleed                 -> file as Tenant Isolation finding
Saga / consumer idempotency       -> escalate; queues are infrastructure, touch operator
```

## Pro tips

1. Start from the ledger or counter, not the UI. The DB is the authoritative source; the UI lies.
2. Compute every total server-side. Any value the client computes and the server accepts is a candidate.
3. Idempotency and retries are first-class concerns. Verify key scope (principal vs path), TTL, and persistence layer.
4. Probe background workers and webhooks separately; they often skip the auth and policy layer.
5. Validate role / feature gates at the service that mutates state, not only at the edge.
6. End-of-period edges (month-end close, trial expiry, DST flip) are gold mines for rounding and window bugs.
7. Use minimal, auditable PoCs. "Two refunds for one charge with these two requests" is stronger than a 50-page report.
8. Map the state machine before testing; flaws cluster on transitions where the server has no enforcement.
