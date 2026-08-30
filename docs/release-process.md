# Release process

This repository has three public Rust crates, published in dependency order:

1. `lenso-capability-organization-invitation`
2. `lenso-capability-organization-invitation-worker`
3. `lenso-organization-invitation-postgres-plugin`

Publication is manual-only from a clean, reviewed `main` checkout through
`.github/workflows/release-plz.yml`. Pushes to `main` can update a Release-plz
PR; merging that PR does not publish. A live release additionally requires the
workflow inputs `live=true` and literal `confirm=publish`.

Before the Plugin can publish, the exact compatible versions of Secrets,
Organization Directory, Organization Membership, Organization Membership
Admin, Access Control, Transactional Notification, Auth SDK, Lenso runtime,
and PostgreSQL Kit dependencies must already exist on crates.io. Git revisions
in this repository are development provenance; Cargo normalizes publishable
dependencies to their version requirements.

## crates.io Trusted Publisher

Trusted Publishing cannot allocate an unowned crate name. For the first
release only, allocate each `0.1.0` crate name in the order above with a
temporary crates.io token restricted to new-package publication, then revoke
it immediately. Do not store that token in Cargo credentials, GitHub secrets,
workflow logs, or shell history.

Configure one crates.io Trusted Publisher for each crate:

- owner: `LioRael`
- repository: `lenso-organization-invitation-plugin`
- workflow: `release-plz.yml`
- environment: unset

The workflow has no `CARGO_REGISTRY_TOKEN` fallback. Its live job requests the
short-lived crates.io credential through GitHub OIDC (`id-token: write`).

## Required gates

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
lenso-contract-codegen check \
  crates/lenso-capability-organization-invitation/capability.json \
  --rust crates/lenso-capability-organization-invitation/src/generated.rs
lenso-contract-codegen check \
  crates/lenso-capability-organization-invitation-worker/capability.json \
  --rust crates/lenso-capability-organization-invitation-worker/src/generated.rs
./scripts/check-repository-boundary.sh
./scripts/check-public-packages.sh
```

Run the six real PostgreSQL acceptance tests with a disposable database before
publication:

```sh
LENSO_ORGANIZATION_INVITATION_TEST_DATABASE_URL=postgres://.../organization_invitation_test \
  cargo test --locked -p lenso-organization-invitation-postgres-plugin \
  --all-features postgres_tests::
```
