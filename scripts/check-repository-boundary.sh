#!/usr/bin/env bash
set -euo pipefail

expected_crates=$'lenso-capability-organization-invitation\nlenso-capability-organization-invitation-worker\nlenso-organization-invitation-agent-tools-plugin\nlenso-organization-invitation-postgres-plugin'
actual_crates="$(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml -print0 | xargs -0 sed -n 's/^name = "\([^"]*\)"/\1/p' | sort)"

if [[ "$actual_crates" != "$expected_crates" ]]; then
  echo "unexpected workspace crate boundary" >&2
  diff -u <(printf '%s\n' "$expected_crates") <(printf '%s\n' "$actual_crates") || true
  exit 1
fi

if rg -n 'path\s*=\s*"(\.\./\.\./|/)' --glob 'Cargo.toml' .; then
  echo "cross-repository or absolute path dependencies are not allowed" >&2
  exit 1
fi

if rg -n 'HashMap|Mutex<.*Vec|in.memory|memory fallback' crates --glob '*.rs'; then
  echo "ambient in-memory durable state is not allowed" >&2
  exit 1
fi

if rg -n 'CREATE (TABLE|INDEX|SCHEMA)|ALTER TABLE|DROP (TABLE|SCHEMA)' \
  crates/lenso-organization-invitation-postgres-plugin/src/lib.rs \
  crates/lenso-organization-invitation-postgres-plugin/src/storage.rs; then
  echo "runtime DDL is not allowed; migrations are operator-managed" >&2
  exit 1
fi

if rg -n 'organization_memberships|access_control_(grants|roles)|notification_(intents|deliveries)|auth_(sessions|credentials)' \
  crates/lenso-organization-invitation-postgres-plugin/migrations; then
  echo "migration crosses another Plugin's owned fact boundary" >&2
  exit 1
fi

if rg -n 'lenso-platform-|lenso-module-|HostBuilder|HostLinkedModule|ModuleManifest' \
  Cargo.toml crates README.md docs --glob '!**/generated.rs'; then
  echo "legacy Lenso framework dependency or API found" >&2
  exit 1
fi

for capability in \
  'lenso.organization-invitation@1' \
  'lenso.organization-invitation-worker@1' \
  'lenso.secrets@1' \
  'lenso.organization-directory@1' \
  'lenso.organization-membership@1' \
  'lenso.organization-membership-admin@1' \
  'lenso.access-control@1' \
  'lenso.notification.transactional@1'; do
  if ! rg -q "$capability" README.md docs crates; then
    echo "documented Organization Invitation Capability boundary is missing: $capability" >&2
    exit 1
  fi
done

for table in \
  organization_invitation_sequences \
  organization_invitations \
  organization_invitation_commands \
  organization_invitation_mutations \
  organization_invitation_activity; do
  if ! rg -q "$table" crates/lenso-organization-invitation-postgres-plugin; then
    echo "owned PostgreSQL table is missing from implementation: $table" >&2
    exit 1
  fi
done
