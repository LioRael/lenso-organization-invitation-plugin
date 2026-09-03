#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
flags=(--locked)
if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  flags+=(--allow-dirty)
fi

public_packages=(
  lenso-capability-organization-invitation
  lenso-capability-organization-invitation-worker
  lenso-organization-invitation-postgres-plugin
)

for package in "${public_packages[@]}"; do
  manifest="crates/$package/Cargo.toml"
  rg -qx 'publish = true' "$manifest" || {
    printf '%s is not explicitly publishable\n' "$package" >&2
    exit 1
  }
done

rg -qx 'publish = false' crates/lenso-organization-invitation-agent-tools-plugin/Cargo.toml || {
  printf '%s must remain private\n' 'lenso-organization-invitation-agent-tools-plugin' >&2
  exit 1
}

for package in \
  lenso-capability-organization-invitation \
  lenso-capability-organization-invitation-worker; do
  "$cargo_bin" package --quiet "${flags[@]}" -p "$package"
done

"$cargo_bin" package --quiet "${flags[@]}" --no-verify \
  -p lenso-organization-invitation-postgres-plugin \
  --config 'patch.crates-io.lenso-capability-organization-invitation.path="crates/lenso-capability-organization-invitation"' \
  --config 'patch.crates-io.lenso-capability-organization-invitation-worker.path="crates/lenso-capability-organization-invitation-worker"'

printf 'public Organization Invitation package archives are valid\n'
