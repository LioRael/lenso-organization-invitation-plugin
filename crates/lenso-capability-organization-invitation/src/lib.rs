//! Generated portable Organization Invitation role contract.

include!("generated.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_surface_is_exact_and_accept_debug_redacts_the_token() {
        assert_eq!(CAPABILITY_ID, "lenso.organization-invitation@1");
        assert_eq!(DESCRIPTOR_VERSION, "1.0.0");
        assert_eq!(
            [
                ACCEPT_OPERATION,
                GET_INVITATION_OPERATION,
                INVITE_OPERATION,
                LIST_INVITATIONS_OPERATION,
                RESEND_OPERATION,
                REVOKE_OPERATION,
            ],
            [
                "accept",
                "get_invitation",
                "invite",
                "list_invitations",
                "resend",
                "revoke",
            ]
        );
        let request = AcceptRequest {
            expected_revision: "1".to_owned(),
            idempotency_key: "accept-1".to_owned(),
            invitation_id: "6a43eca2-af4b-4897-8514-c4bf069ade77".to_owned(),
            token: "must-never-appear-in-debug".to_owned(),
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&request.token));
    }
}
