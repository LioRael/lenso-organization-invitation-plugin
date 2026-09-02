#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
flags=(--locked)
if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  flags+=(--allow-dirty)
fi

for manifest in crates/*/Cargo.toml; do
  rg -qx 'publish = true' "$manifest" || {
    printf '%s is not explicitly publishable\n' "$manifest" >&2
    exit 1
  }
done

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
