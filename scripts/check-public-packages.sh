#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
consumer_cargo_bin="${LENSO_CONSUMER_CARGO_BIN:-cargo}"
repository_root="$(git rev-parse --show-toplevel)"
verification_root="$(mktemp -d "${TMPDIR:-/tmp}/lenso-organization-invitation-packages.XXXXXX")"
workspace_copy="$verification_root/repository"

cleanup() {
  if [[ "${LENSO_KEEP_PACKAGE_TMP:-0}" == "1" ]]; then
    printf 'kept package verification root: %s\n' "$verification_root" >&2
  else
    rm -r "$verification_root"
  fi
}
trap cleanup EXIT

mkdir -p "$workspace_copy"
tar --exclude=.git --exclude=target -C "$repository_root" -cf - . | tar -C "$workspace_copy" -xf -

offline_flags=()
if [[ "${LENSO_PACKAGE_OFFLINE:-0}" == "1" ]]; then
  offline_flags+=(--offline)
fi

source_checkout() {
  local environment_name="$1"
  local repository="$2"
  local revision="$3"
  local directory="$4"
  local configured="${!environment_name:-}"
  if [[ -n "$configured" ]]; then
    git -C "$configured" rev-parse --is-inside-work-tree >/dev/null || return
    printf '%s\n' "$configured"
    return
  fi
  local checkout="$verification_root/$directory"
  git clone --quiet --filter=blob:none --no-checkout "$repository" "$checkout" || return
  git -C "$checkout" checkout --quiet --detach "$revision" || return
  printf '%s\n' "$checkout"
}

access_root="$(source_checkout LENSO_ACCESS_CONTROL_SOURCE https://github.com/LioRael/lenso-access-control-plugin de1e1f1ec61232b13fc90a05f1cb4e3fc96ba420 access-control)"
organization_root="$(source_checkout LENSO_ORGANIZATION_SOURCE https://github.com/LioRael/lenso-organization-plugin 9572afd465ba2f952b646ec16935c0274f66c82a organization)"
notification_root="$(source_checkout LENSO_NOTIFICATION_SOURCE https://github.com/LioRael/lenso-notification-plugin b001dffea970789858499efa2049853d37bc3e0f notification)"
secrets_root="$(source_checkout LENSO_SECRETS_SOURCE https://github.com/LioRael/lenso-secrets-plugin c31aa142ff59b4536e2bf3e9785ccbb5bb5c0e6a secrets)"

package_dependency() {
  local source_root="$1"
  local package_name="$2"
  "$cargo_bin" package --quiet --locked "${offline_flags[@]}" \
    --manifest-path "$source_root/Cargo.toml" -p "$package_name" || return
  local metadata
  metadata="$("$cargo_bin" metadata --no-deps --format-version=1 --manifest-path "$source_root/Cargo.toml")" || return
  local target_directory
  target_directory="$(jq -r '.target_directory' <<<"$metadata")" || return
  local version
  version="$(jq -r --arg name "$package_name" '.packages[] | select(.name == $name) | .version' <<<"$metadata")" || return
  local archive="$target_directory/package/$package_name-$version.crate"
  [[ -f "$archive" ]] || return
  tar -xzf "$archive" -C "$verification_root" || return
  printf '%s\n' "$verification_root/$package_name-$version"
}

# These archives model the already-published dependency order. Their normalized
# manifests all resolve the same registry Runtime/Kernel/authoring identities,
# avoiding a false pass caused by mixing registry and git trait identities.
access_package="$(package_dependency "$access_root" lenso-capability-access-control)"
directory_package="$(package_dependency "$organization_root" lenso-capability-organization-directory)"
membership_package="$(package_dependency "$organization_root" lenso-capability-organization-membership)"
membership_admin_package="$(package_dependency "$organization_root" lenso-capability-organization-membership-admin)"
notification_package="$(package_dependency "$notification_root" lenso-capability-notification-transactional)"
secrets_package="$(package_dependency "$secrets_root" lenso-capability-secrets)"

for capability in \
  lenso-capability-organization-invitation \
  lenso-capability-organization-invitation-worker; do
  "$cargo_bin" package --quiet --locked "${offline_flags[@]}" \
    --manifest-path "$workspace_copy/Cargo.toml" -p "$capability"
done

patches=(
  --config "patch.crates-io.lenso-capability-organization-invitation.path=\"$workspace_copy/crates/lenso-capability-organization-invitation\""
  --config "patch.crates-io.lenso-capability-organization-invitation-worker.path=\"$workspace_copy/crates/lenso-capability-organization-invitation-worker\""
  --config "patch.crates-io.lenso-capability-access-control.path=\"$access_root/crates/lenso-capability-access-control\""
  --config "patch.crates-io.lenso-capability-organization-directory.path=\"$organization_root/crates/lenso-capability-organization-directory\""
  --config "patch.crates-io.lenso-capability-organization-membership.path=\"$organization_root/crates/lenso-capability-organization-membership\""
  --config "patch.crates-io.lenso-capability-organization-membership-admin.path=\"$organization_root/crates/lenso-capability-organization-membership-admin\""
  --config "patch.crates-io.lenso-capability-notification-transactional.path=\"$notification_root/crates/lenso-capability-notification-transactional\""
  --config "patch.crates-io.lenso-capability-secrets.path=\"$secrets_root/crates/lenso-capability-secrets\""
)

"$cargo_bin" "${patches[@]}" package --quiet --no-verify "${offline_flags[@]}" \
  --manifest-path "$workspace_copy/Cargo.toml" \
  -p lenso-organization-invitation-postgres-plugin

metadata="$("$cargo_bin" metadata --no-deps --format-version=1 --manifest-path "$workspace_copy/Cargo.toml")"
target_directory="$(jq -r '.target_directory' <<<"$metadata")"
public_version="$(jq -r '.packages[] | select(.name == "lenso-capability-organization-invitation") | .version' <<<"$metadata")"
worker_version="$(jq -r '.packages[] | select(.name == "lenso-capability-organization-invitation-worker") | .version' <<<"$metadata")"
plugin_version="$(jq -r '.packages[] | select(.name == "lenso-organization-invitation-postgres-plugin") | .version' <<<"$metadata")"

for archive in \
  "$target_directory/package/lenso-capability-organization-invitation-$public_version.crate" \
  "$target_directory/package/lenso-capability-organization-invitation-worker-$worker_version.crate" \
  "$target_directory/package/lenso-organization-invitation-postgres-plugin-$plugin_version.crate"; do
  [[ -f "$archive" ]]
  tar -xzf "$archive" -C "$verification_root"
done

public_package="$verification_root/lenso-capability-organization-invitation-$public_version"
worker_package="$verification_root/lenso-capability-organization-invitation-worker-$worker_version"
plugin_package="$verification_root/lenso-organization-invitation-postgres-plugin-$plugin_version"

# Cargo-clippy performs its own Cargo discovery, so persist the temporary
# consumer patches inside the extracted package instead of relying on parent
# process CLI flags. This file lives only under the mktemp verification root.
mkdir -p "$plugin_package/.cargo"
{
  printf '[patch.crates-io]\n'
  printf 'lenso-capability-organization-invitation = { path = "%s" }\n' "$public_package"
  printf 'lenso-capability-organization-invitation-worker = { path = "%s" }\n' "$worker_package"
  printf 'lenso-capability-access-control = { path = "%s" }\n' "$access_package"
  printf 'lenso-capability-organization-directory = { path = "%s" }\n' "$directory_package"
  printf 'lenso-capability-organization-membership = { path = "%s" }\n' "$membership_package"
  printf 'lenso-capability-organization-membership-admin = { path = "%s" }\n' "$membership_admin_package"
  printf 'lenso-capability-notification-transactional = { path = "%s" }\n' "$notification_package"
  printf 'lenso-capability-secrets = { path = "%s" }\n' "$secrets_package"
} >"$plugin_package/.cargo/config.toml"

(
  cd "$plugin_package"
  "$consumer_cargo_bin" generate-lockfile "${offline_flags[@]}"
  "$consumer_cargo_bin" check --quiet --locked --all-targets --all-features "${offline_flags[@]}"
  "$consumer_cargo_bin" test --quiet --locked --all-targets --all-features "${offline_flags[@]}"
  "$consumer_cargo_bin" clippy --quiet --locked --all-targets --all-features "${offline_flags[@]}" -- -D warnings
)
