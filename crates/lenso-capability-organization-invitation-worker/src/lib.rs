//! Generated portable Organization Invitation worker role contract.

include!("generated.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_role_is_separate_and_bounded() {
        assert_eq!(CAPABILITY_ID, "lenso.organization-invitation-worker@1");
        assert_eq!(
            [DISPATCH_DUE_OPERATION, EXPIRE_DUE_OPERATION],
            ["dispatch_due", "expire_due"]
        );
    }
}
