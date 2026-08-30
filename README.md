# Lenso Organization Invitation Plugin

Removable organization invitation lifecycle for Lenso. It issues and rotates
single-use email invitation tokens, converges accepted invitations through the
Organization Membership Admin Capability, and delivers invitation and lifecycle
notifications through a durable PostgreSQL command ledger.

The Plugin provides two portable roles:

- `lenso.organization-invitation@1`: `invite`, `get_invitation`,
  `list_invitations`, `resend`, `revoke`, and `accept`;
- `lenso.organization-invitation-worker@1`: bounded `expire_due` and
  `dispatch_due` batches.

Each Organization gets stable `INV-N` identifiers. Every mutation uses a
positive decimal revision as a compare-and-swap token and a caller-scoped
idempotency key. Lists use an opaque `(created_at, invitation_id)` keyset cursor
and return at most 100 records.

## Security and authority

The database stores only an Argon2id verifier made from a random salt and a
separate pepper. The 256-bit invitation token is derived in-process from a
distinct secret, returned only for the transaction that first commits an
`invite` or `resend`, and never stored in PostgreSQL. Resend rotates the token
generation and invalidates every older token.

Management and worker calls require all of the following:

1. an exact calling Plugin Instance from the role-specific allowlist;
2. a valid Actor Assertion audienced to the exact Capability operation;
3. active Organization Membership for the asserted subject;
4. an Access Control grant for the operation's Organization-scoped permission.

Acceptance has a separate exact caller allowlist and user Actor Assertion. The
single-use token is its resource-local proof; an invitee is not required to be
an Organization member before acceptance. RBAC policy, memberships, and
Organization facts remain owned by their independent providers.

See [the Plugin card](docs/plugin-card.md) for the complete authority and state
model and [PostgreSQL operations](docs/postgresql-operations.md) for setup,
recovery, and worker procedures.

## Operator workflow

1. Run `OrganizationInvitationOperator::setup` or `upgrade` against the
   Plugin-owned PostgreSQL schema. Runtime activation never runs DDL.
2. Store three distinct Secrets references: database URL, token pepper, and
   token derivation secret. Both token secrets must contain at least 256 bits.
3. Configure exact management, acceptance, and worker caller allowlists; an
   Auth Actor Assertion verification key; a query-free HTTPS acceptance URL;
   and bounded token/lease/retry settings.
4. Bind Secrets, Organization Directory, Organization Membership,
   Organization Membership Admin, Access Control, and Transactional
   Notification providers.
5. Invoke `dispatch_due` until `has_more=false`; invoke `expire_due` on a
   schedule until `has_more=false`. Both operations are bounded and
   idempotent.

There is no in-memory fallback and no background task hidden in activation.
Removing the Plugin Instance removes invitation behavior; dropping its owned
schema is a separate operator decision.

## Verification

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
./scripts/check-repository-boundary.sh
```

Real acceptance tests require a disposable database whose name contains
`test`:

```sh
LENSO_ORGANIZATION_INVITATION_TEST_DATABASE_URL=postgres://.../organization_invitation_test \
  cargo test --locked --workspace --all-targets --all-features
```

Publication and crates.io Trusted Publisher setup are documented in
[the release process](docs/release-process.md).
