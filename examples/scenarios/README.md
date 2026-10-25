# Stateful scenarios

A scenario is a **sequence of dependent requests**, not a replay. The runner logs in as
two accounts, sends each step through the scope gate, substitutes variables from earlier
responses, and evaluates a deterministic claim.

```bash
bb scenario run --file examples/scenarios/idor-write.json \
  --program acme --accounts data/acme.accounts.json --allow-write
```

## From a HAR

Draft scenarios from authenticated browsing without writing them by hand:

```bash
bb scenario propose --har ~/Downloads/app.har --program acme
```

It clusters a captured create with later reads/mutations/deletes and writes drafts plus a
`REVIEW.md` under `data/proposed/`. It never executes anything; the captured session is assumed
to be the owner (A), so verify roles and redacted body values before running a draft.

## Schema 2

`multi-role-state-change.json` shows the opt-in schema 2 shape: a `roles` map with three labels,
JSON assertions, and a `state_change` claim verified by a second role. Existing A/B files keep
working unchanged; new fields require `"schema": 2`.

```bash
bb scenario run --file examples/scenarios/multi-role-state-change.json \
  --program acme --accounts data/acme.accounts.json --allow-write
```

## Steps

| Field | Meaning |
|---|---|
| `id` | Name used by `extract`, `claim`, and cleanup references |
| `role` | `A` (owner) or `B` (attacker) |
| `method` / `path` | Request; relative to `base_url` or the accounts file |
| `json` / `data` / `params` | Body and query, with `${...}` substitution |
| `expect` | `status`, `body_contains`, `body_not_contains` — sanity checks, not the verdict |
| `extract` | `{"item_id": "$.data.id"}` — dotted JSON path, available to later steps |

Built-in variables: `${A.email}`, `${A.id}`, `${B.email}`, `${B.id}`, `${marker}`,
`${run_id}`. Extracted values are also available by name.

## Claims

`idor_read` — the `step` must return 2xx, contain the owner's identity, and not contain
the attacker's identity. Add `owner_step` (the owner's own baseline request); without it the
report has no owner-side evidence and the runner logs a warning.

`idor_write` — `mutate` must return 2xx and the owner's `verify` step must observe the
`marker` written by the attacker.

A denied attacker (`401/403/404`) yields **enforced** — coverage, not a finding. Anything
else is **inconclusive**; no report is produced.

## Safety

- Every non-GET/HEAD step requires `--allow-write`. Without it the runner refuses before
  sending anything.
- Use disposable accounts and disposable resources. `cleanup` runs only with
  `--allow-write`, only after the run, and only against objects the scenario created.
- `--dry-run` resolves and plans requests without sending; use it before the first write.
- The base URL and every step still pass the scope engine. Do not point this at a program
  that does not authorise the test.
