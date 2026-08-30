# Organization Invitation Plugin card

## Outcome

An authorized Organization member can invite an email address, inspect the
invitation, rotate its token, or revoke it. The invited user can consume the
token once; the Plugin then converges Organization membership and records the
provider receipt before reporting acceptance complete.

## Package and slots

- Plugin package: `lenso-organization-invitation-postgres-plugin`
- Plugin id: `lenso.organization-invitation.postgres`
- Root slot: `organization-invitation`
- Public Capability: `lenso.organization-invitation@1`
- Worker Capability: `lenso.organization-invitation-worker@1`

## Provides

The public role has six request operations:

- `invite`: create one pending invitation for a normalized email;
- `get_invitation`: resolve a stable UUID or Organization-local `INV-N`;
- `list_invitations`: filter by state or normalized email with a bounded
  keyset page;
- `resend`: CAS-rotate the token and supersede older delivery commands;
- `revoke`: CAS-transition a pending invitation to `revoked`;
- `accept`: consume the token and converge membership exactly once.

The separate worker role has two bounded request operations:

- `expire_due`: lock at most 100 due invitations with `SKIP LOCKED` and
  transition them to `expired`;
- `dispatch_due`: lease at most 100 durable notification or membership
  commands, execute them through typed Ports, and persist receipts or retry
  state.

## Requires

- `lenso.secrets@1`: `resolve` three distinct secret references;
- `lenso.organization-directory@1`: `get_organization` before creation and
  delivery;
- `lenso.organization-membership@1`: `check_membership` for management and
  worker actors;
- `lenso.access-control@1`: `check_permission` on Organization scope;
- `lenso.organization-membership-admin@1`: idempotent `add_member` on
  acceptance;
- `lenso.notification.transactional@1`:
  `create_organization_invitation` and `observe_invitation_lifecycle`;
- signed Auth Actor Assertions verified at the exact target operation.

All required Capabilities have cardinality `one`. The implementation uses
their generated clients and never reads another Plugin's tables.

## Authorization

Management callers and permissions:

- `get_invitation`, `list_invitations`:
  `organization.invitations.read`;
- `invite`, `resend`, `revoke`:
  `organization.invitations.manage`.

Worker callers and permissions:

- `expire_due`: `organization.invitations.expire`;
- `dispatch_due`: `organization.invitations.dispatch`.

Management and acceptance assertions require actor kind `user`. Worker
assertions allow `user` or `service_account`; either kind must still be an
active Organization member and have the worker permission. Exact caller
allowlists are immutable configuration and do not replace Access Control.

Acceptance deliberately skips pre-existing membership and Access Control:
the invitee does not have those facts yet. Its exact caller, exact user Actor
Assertion, invitation UUID, unexpired single-use token, observed generation,
and CAS revision are checked together under a row lock.

## Owned facts

The owned PostgreSQL schema contains:

- stable UUIDs and per-Organization `INV-N` sequences;
- normalized email, inviter, acceptance subject, state, revision, and
  timestamps;
- Argon2id token verifier, generation, expiry, and consumption time;
- caller-scoped idempotency mutations and sanitized response receipts;
- durable commands, leases, attempts, backoff, provider receipts, and
  supersession state;
- append-only local activity evidence for creation, resend, acceptance,
  revocation, expiry, and terminal acceptance failure.

It does not own Organizations, memberships, permission grants, notification
delivery internals, Auth credentials, or RBAC policy.

## State and concurrency model

| Current | Event | Next | Guard |
| --- | --- | --- | --- |
| none | invite | pending | active Organization, no pending normalized email |
| pending | resend | pending | expected revision, no acceptance in progress |
| pending | revoke | revoked | expected revision, no acceptance in progress |
| pending | deadline | expired | token due, no acceptance in progress |
| pending | accept start | pending / acceptance pending | token, generation, revision, row lock |
| acceptance pending | membership receipt | accepted | matching command lease fence |
| acceptance pending | permanent membership rejection | expired | failed command receipt/activity |

The partial unique index permits only one pending invitation per normalized
email and Organization. An advisory transaction lock makes the domain result
deterministic before the index is reached. Every mutation is serialized under
the invitation row and compares a positive decimal revision. Worker claims use
`FOR UPDATE SKIP LOCKED`; completion, retry, failure, and supersession require
the exact lease UUID.

## Token and side-effect safety

Tokens are base64url-encoded 256-bit HMAC output. Derivation and pepper keys
are independent 256-bit Secrets values. PostgreSQL stores a random-salt
Argon2id v19 verifier with 19 MiB memory, two iterations, and one lane; it never
stores token plaintext. Generated request/response Debug implementations redact
token fields.

`invite`, `resend`, and `accept` commit local intent before crossing a Plugin
boundary. Command keys are stable downstream idempotency keys. A timeout or
Runtime failure is retried with the same key after a fenced lease expires;
known permanent domain rejections are not replayed indefinitely. A crash after
an external success but before the local receipt is therefore recovered by the
provider's idempotent replay rather than a new effect.

## Lifecycle and removal

`activate` resolves Secrets, validates the authored migration history, and
opens the owned schema. It does not create, upgrade, or repair schema objects.
`deactivate` closes the pool and drops in-process secret bytes.

Removing the Plugin Instance and its bindings stops all invitation behavior.
Dropping its schema removes local invitation records and command evidence.
Already-created Organization memberships and Notification-provider receipts
remain owned by those providers and follow their retention policies.

## Deliberate v1 limits

- Email normalization is conservative ASCII lowercase normalization; there is
  no provider-specific alias folding or internationalized mailbox handling.
- Tokens cannot be recovered. Losing the one-time response requires an
  authorized `resend` and revision CAS.
- There is no pepper/derivation-key rotation protocol in v1.
- A known permanent Membership Admin rejection ends the invitation as
  `expired`; a new invitation is required after the provider problem is fixed.
- Notification dispatch is asynchronous. A committed invitation can exist
  while its notification is pending or failed; the worker result exposes that
  outcome and the invitation exposes `delivery_state`.
- This Plugin supplies product behavior and technical controls; it makes no
  legal, regulatory, or deliverability guarantee.
