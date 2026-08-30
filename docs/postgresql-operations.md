# PostgreSQL operations

## Schema ownership

Choose a dedicated PostgreSQL schema for each Plugin Instance. The configured
schema is the only database namespace this Plugin owns. Runtime SQL uses the
owned connection search path and never accesses Organization, Access Control,
Auth, Secrets, or Notification tables.

Schema changes are operator-managed:

```rust
OrganizationInvitationOperator::setup(database_url, "organization_invitation_v1").await?;
OrganizationInvitationOperator::upgrade(database_url, "organization_invitation_v1").await?;
```

`setup` installs the authored migration plan. `upgrade` applies pending
migrations and is safe to repeat. Activation fails closed if the configured
schema or migration history is missing or incompatible; it never performs DDL.

## Secrets

Configure distinct references for:

- `database_url_secret`;
- `token_pepper_secret`;
- `token_derivation_secret`.

The token secrets must each resolve to at least 32 bytes and must not be equal.
Changing either token secret without an explicit rotation migration invalidates
pending tokens or delivery reconstruction, so v1 treats them as immutable.

## Worker scheduling

Call `expire_due` and `dispatch_due` per Organization with a unique
caller-scoped idempotency key. Each batch limit must be between 1 and 100.
Continue while `has_more=true`; use a new idempotency key for the next batch.

Suggested scheduling behavior:

- expire every minute for Organizations with active invitations;
- dispatch continuously while `has_more=true`, then poll with bounded jitter;
- alert when `permanent_failed` is nonzero or an invitation has
  `delivery_state=failed`;
- never run SQL to mark a command complete without a provider receipt.

Runtime failures retain the same downstream idempotency key and are retried
with exponential backoff capped at 24 hours. Commands use a configurable lease.
After a worker crash, another worker can reclaim only after `lease_until`; its
new UUID fence prevents the stale worker from committing completion or retry.

## Backup, restore, and restart

Back up the entire owned schema atomically. The invitation, mutation, command,
and activity tables are one consistency unit. Restore all of them to the same
point; restoring invitations without commands can lose membership or
notification convergence, while restoring commands without mutation receipts
can break exact replay.

After restore or process restart:

1. run the authored `upgrade` workflow;
2. activate the Plugin against the restored schema;
3. resume `dispatch_due` with fresh batch idempotency keys;
4. continue `expire_due` for overdue tokens;
5. inspect failed commands and activity before dropping any evidence.

Do not shorten live command leases during restart. The worker will reclaim a
stranded command after its persisted deadline and reuse the exact downstream
idempotency key.

## Acceptance test safety

The `postgres-acceptance` feature requires
`LENSO_ORGANIZATION_INVITATION_TEST_DATABASE_URL`. The database name must
contain `test`; every test creates and drops a unique schema. The suite proves:

- restart persistence and caller-scoped replay;
- concurrent same-email uniqueness and revision CAS;
- resend invalidation of the old token and stable keyset pages;
- concurrent token acceptance and one membership command;
- concurrent `SKIP LOCKED` expiry without duplicate activity;
- crash recovery, lease fencing, provider receipt persistence, and absence of
  token plaintext from command rows.
