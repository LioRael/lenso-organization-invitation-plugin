use lenso_postgres_kit::OwnedPostgres;
use sqlx::{AssertSqlSafe, Executor as _, Row as _};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{OrganizationInvitationOperator, schema, storage, token};

const DERIVATION_SECRET: [u8; 32] = [0x41; 32];
const TOKEN_PEPPER: [u8; 32] = [0x52; 32];
const TOKEN_TTL_SECONDS: i64 = 3_600;

struct TestDatabase {
    database_url: String,
    schema_name: String,
    postgres: OwnedPostgres,
}

impl TestDatabase {
    async fn prepare() -> Option<Self> {
        let Ok(database_url) = std::env::var("LENSO_ORGANIZATION_INVITATION_TEST_DATABASE_URL")
        else {
            eprintln!(
                "skipping PostgreSQL acceptance; \
                 LENSO_ORGANIZATION_INVITATION_TEST_DATABASE_URL is unset"
            );
            return None;
        };
        let database_name = database_url
            .split('?')
            .next()
            .and_then(|value| value.rsplit('/').next())
            .unwrap_or_default();
        assert!(
            database_name.contains("test"),
            "acceptance requires a disposable database whose name contains `test`"
        );
        let schema_name = format!("organization_invitation_test_{}", Uuid::new_v4().simple());
        OrganizationInvitationOperator::setup(&database_url, &schema_name)
            .await
            .expect("set up Organization Invitation schema");
        OrganizationInvitationOperator::upgrade(&database_url, &schema_name)
            .await
            .expect("repeat migration plan");
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema::schema_plan(schema_name.clone()).expect("valid schema plan"),
        )
        .await
        .expect("prepare owned PostgreSQL connection");
        Some(Self {
            database_url,
            schema_name,
            postgres,
        })
    }

    async fn restart(&mut self) {
        self.postgres.pool().close().await;
        self.postgres = OwnedPostgres::prepare(
            &self.database_url,
            schema::schema_plan(self.schema_name.clone()).expect("valid schema plan"),
        )
        .await
        .expect("restart owned PostgreSQL connection");
    }

    async fn cleanup(self) {
        self.postgres.pool().close().await;
        let cleanup = sqlx::PgPool::connect(&self.database_url)
            .await
            .expect("connect for schema cleanup");
        cleanup
            .execute(AssertSqlSafe(format!(
                "DROP SCHEMA \"{}\" CASCADE",
                self.schema_name
            )))
            .await
            .expect("drop test schema");
        cleanup.close().await;
    }
}

struct CreatedInvitation {
    result: storage::TokenOperationResult,
    token: Zeroizing<String>,
}

async fn create_invitation(
    postgres: &OwnedPostgres,
    organization_id: &str,
    email: &str,
    caller: &str,
    idempotency_key: &str,
) -> CreatedInvitation {
    let invitation_id = Uuid::new_v4();
    let token =
        token::derive_token(&DERIVATION_SECRET, invitation_id, 1).expect("derive invitation token");
    let token_hash = token::hash_token(&token, &TOKEN_PEPPER).expect("hash invitation token");
    let result = storage::create_invitation(
        postgres,
        caller,
        idempotency_key,
        idempotency_key.as_bytes(),
        invitation_id,
        organization_id,
        "usr_inviter",
        email,
        email,
        &token_hash,
        TOKEN_TTL_SECONDS,
    )
    .await
    .expect("create invitation storage operation")
    .expect("create invitation domain operation");
    CreatedInvitation { result, token }
}

#[tokio::test]
async fn setup_restart_and_caller_scoped_replay_are_durable() {
    let Some(mut database) = TestDatabase::prepare().await else {
        return;
    };
    let created = create_invitation(
        &database.postgres,
        "org_restart",
        "member@example.com",
        "admin-api",
        "invite-restart-1",
    )
    .await;
    assert!(created.result.disclose_token);

    let stored_hash: String = sqlx::query_scalar(
        "SELECT token_hash FROM organization_invitations WHERE invitation_id=$1",
    )
    .bind(created.result.invitation.invitation_id)
    .fetch_one(database.postgres.pool())
    .await
    .expect("read stored token hash");
    assert!(stored_hash.starts_with("$argon2id$v=19$"));
    assert!(!stored_hash.contains(created.token.as_str()));

    database.restart().await;
    let replay = storage::create_invitation(
        &database.postgres,
        "admin-api",
        "invite-restart-1",
        b"invite-restart-1",
        Uuid::new_v4(),
        "org_restart",
        "usr_inviter",
        "member@example.com",
        "member@example.com",
        "not-used-on-replay",
        TOKEN_TTL_SECONDS,
    )
    .await
    .expect("replay invitation storage operation")
    .expect("replay invitation domain operation");
    assert_eq!(replay.invitation, created.result.invitation);
    assert!(
        !replay.disclose_token,
        "a replay must not disclose the token again"
    );

    let other_caller = storage::create_invitation(
        &database.postgres,
        "another-admin-api",
        "invite-restart-1",
        b"invite-restart-1",
        Uuid::new_v4(),
        "org_restart",
        "usr_inviter",
        "another@example.com",
        "another@example.com",
        &token::hash_token("another-valid-token-material", &TOKEN_PEPPER).unwrap(),
        TOKEN_TTL_SECONDS,
    )
    .await
    .expect("other caller storage operation")
    .expect("caller-scoped idempotency");
    assert_ne!(
        other_caller.invitation.invitation_id,
        replay.invitation.invitation_id
    );
    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_same_email_and_revision_mutations_are_serialized() {
    let Some(database) = TestDatabase::prepare().await else {
        return;
    };
    let first_id = Uuid::new_v4();
    let second_id = Uuid::new_v4();
    let first_token = token::derive_token(&DERIVATION_SECRET, first_id, 1).unwrap();
    let second_token = token::derive_token(&DERIVATION_SECRET, second_id, 1).unwrap();
    let first_hash = token::hash_token(&first_token, &TOKEN_PEPPER).unwrap();
    let second_hash = token::hash_token(&second_token, &TOKEN_PEPPER).unwrap();
    let first = storage::create_invitation(
        &database.postgres,
        "admin-api",
        "same-email-1",
        b"same-email-1",
        first_id,
        "org_concurrency",
        "usr_inviter",
        "Member@Example.COM",
        "member@example.com",
        &first_hash,
        TOKEN_TTL_SECONDS,
    );
    let second = storage::create_invitation(
        &database.postgres,
        "admin-api",
        "same-email-2",
        b"same-email-2",
        second_id,
        "org_concurrency",
        "usr_inviter",
        "member@example.com",
        "member@example.com",
        &second_hash,
        TOKEN_TTL_SECONDS,
    );
    let (first, second) = tokio::join!(first, second);
    let outcomes = [first.unwrap(), second.unwrap()];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(storage::DomainFailure::InvitationExists)))
            .count(),
        1
    );
    let invitation = outcomes.into_iter().find_map(Result::ok).unwrap();

    let resend_token = token::derive_token(
        &DERIVATION_SECRET,
        invitation.invitation.invitation_id,
        invitation.token_generation + 1,
    )
    .unwrap();
    let resend_hash = token::hash_token(&resend_token, &TOKEN_PEPPER).unwrap();
    let resend = storage::resend_invitation(
        &database.postgres,
        "admin-api",
        "resend-race",
        b"resend-race",
        "org_concurrency",
        invitation.invitation.invitation_id,
        "usr_admin",
        invitation.invitation.revision,
        &resend_hash,
        TOKEN_TTL_SECONDS,
    );
    let revoke = storage::revoke_invitation(
        &database.postgres,
        "admin-api",
        "revoke-race",
        b"revoke-race",
        "org_concurrency",
        invitation.invitation.invitation_id,
        "usr_admin",
        invitation.invitation.revision,
        "security review",
    );
    let (resend, revoke) = tokio::join!(resend, revoke);
    let resend = resend.unwrap();
    let revoke = revoke.unwrap();
    assert_eq!(usize::from(resend.is_ok()) + usize::from(revoke.is_ok()), 1);
    assert_eq!(
        usize::from(matches!(
            resend,
            Err(storage::DomainFailure::RevisionConflict)
        )) + usize::from(matches!(
            revoke,
            Err(storage::DomainFailure::RevisionConflict)
        )),
        1
    );
    database.cleanup().await;
}

#[tokio::test]
async fn resend_invalidates_old_token_and_list_uses_stable_keyset_pages() {
    let Some(database) = TestDatabase::prepare().await else {
        return;
    };
    let first = create_invitation(
        &database.postgres,
        "org_pages",
        "first@example.com",
        "admin-api",
        "page-create-1",
    )
    .await;
    let new_token =
        token::derive_token(&DERIVATION_SECRET, first.result.invitation.invitation_id, 2).unwrap();
    let new_hash = token::hash_token(&new_token, &TOKEN_PEPPER).unwrap();
    let resent = storage::resend_invitation(
        &database.postgres,
        "admin-api",
        "page-resend-1",
        b"page-resend-1",
        "org_pages",
        first.result.invitation.invitation_id,
        "usr_admin",
        first.result.invitation.revision,
        &new_hash,
        TOKEN_TTL_SECONDS,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(resent.token_generation, 2);
    let stored =
        storage::get_invitation_by_id(&database.postgres, first.result.invitation.invitation_id)
            .await
            .unwrap()
            .unwrap();
    let stored_hash = stored.token_hash.as_deref().unwrap();
    assert!(!token::verify_token(&first.token, &TOKEN_PEPPER, stored_hash).unwrap());
    assert!(token::verify_token(&new_token, &TOKEN_PEPPER, stored_hash).unwrap());

    let replay = storage::resend_invitation(
        &database.postgres,
        "admin-api",
        "page-resend-1",
        b"page-resend-1",
        "org_pages",
        first.result.invitation.invitation_id,
        "usr_admin",
        first.result.invitation.revision,
        "ignored-on-replay",
        TOKEN_TTL_SECONDS,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!replay.disclose_token);

    for number in 2..=5 {
        create_invitation(
            &database.postgres,
            "org_pages",
            &format!("member-{number}@example.com"),
            "admin-api",
            &format!("page-create-{number}"),
        )
        .await;
    }
    let first_page = storage::list_invitations(
        &database.postgres,
        &storage::InvitationFilters {
            organization_id: "org_pages",
            state: None,
            email_normalized: None,
            cursor: None,
            limit: 2,
        },
    )
    .await
    .unwrap();
    assert_eq!(first_page.len(), 2);
    let cursor_value = storage::encode_invitation_cursor(first_page.last().unwrap()).unwrap();
    let cursor = storage::decode_invitation_cursor(&cursor_value).unwrap();
    let second_page = storage::list_invitations(
        &database.postgres,
        &storage::InvitationFilters {
            organization_id: "org_pages",
            state: None,
            email_normalized: None,
            cursor: Some(&cursor),
            limit: 2,
        },
    )
    .await
    .unwrap();
    assert_eq!(second_page.len(), 2);
    assert!(first_page.iter().all(|left| {
        second_page
            .iter()
            .all(|right| left.invitation_id != right.invitation_id)
    }));
    database.cleanup().await;
}

#[tokio::test]
async fn acceptance_race_creates_one_membership_command_and_exact_replay() {
    let Some(database) = TestDatabase::prepare().await else {
        return;
    };
    let created = create_invitation(
        &database.postgres,
        "org_accept",
        "invitee@example.com",
        "admin-api",
        "accept-create-1",
    )
    .await;
    let invitation_id = created.result.invitation.invitation_id;
    let stored = storage::get_invitation_by_id(&database.postgres, invitation_id)
        .await
        .unwrap()
        .unwrap();
    let stored_hash = stored.token_hash.as_deref().unwrap().to_owned();
    assert!(token::verify_token(&created.token, &TOKEN_PEPPER, &stored_hash).unwrap());

    let first = storage::begin_accept(
        &database.postgres,
        "accept-api",
        "accept-race-1",
        b"accept-race-1",
        invitation_id,
        "usr_invitee_a",
        1,
        1,
        &stored_hash,
        30,
    );
    let second = storage::begin_accept(
        &database.postgres,
        "accept-api",
        "accept-race-2",
        b"accept-race-2",
        invitation_id,
        "usr_invitee_b",
        1,
        1,
        &stored_hash,
        30,
    );
    let (first, second) = tokio::join!(first, second);
    let outcomes = [first.unwrap(), second.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(storage::AcceptStart::Execute(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                Err(storage::DomainFailure::RevisionConflict
                    | storage::DomainFailure::AcceptanceInProgress)
            ))
            .count(),
        1
    );
    let command = outcomes
        .into_iter()
        .find_map(|outcome| match outcome {
            Ok(storage::AcceptStart::Execute(command)) => Some(command),
            _ => None,
        })
        .unwrap();
    let accepted = storage::complete_accept(&database.postgres, &command, "member_1", "2")
        .await
        .unwrap();
    assert_eq!(accepted.state, "accepted");
    assert_eq!(accepted.membership_id, "member_1");
    assert_eq!(
        storage::complete_accept(&database.postgres, &command, "member_1", "2")
            .await
            .unwrap(),
        accepted
    );

    let successful_actor = command.acceptance_subject.as_deref().unwrap();
    let successful_key = if successful_actor == "usr_invitee_a" {
        "accept-race-1"
    } else {
        "accept-race-2"
    };
    let replay = storage::lookup_accept_replay(
        &database.postgres,
        "accept-api",
        successful_key,
        successful_actor,
        successful_key.as_bytes(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(replay, Some(storage::AcceptStart::Replay(value)) if value == accepted));
    let membership_commands: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organization_invitation_commands WHERE invitation_id=$1 AND kind='add_member'",
    )
    .bind(invitation_id)
    .fetch_one(database.postgres.pool())
    .await
    .unwrap();
    assert_eq!(membership_commands, 1);
    let provider_receipt: serde_json::Value = sqlx::query_scalar(
        "SELECT provider_receipt FROM organization_invitation_commands WHERE command_id=$1",
    )
    .bind(command.command_id)
    .fetch_one(database.postgres.pool())
    .await
    .unwrap();
    assert_eq!(provider_receipt["membership_id"], "member_1");
    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_expiry_workers_skip_locked_without_duplicate_activity() {
    let Some(database) = TestDatabase::prepare().await else {
        return;
    };
    for number in 1..=4 {
        create_invitation(
            &database.postgres,
            "org_expire",
            &format!("expired-{number}@example.com"),
            "admin-api",
            &format!("expire-create-{number}"),
        )
        .await;
    }
    sqlx::query(
        "UPDATE organization_invitations SET token_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE organization_id='org_expire'",
    )
    .execute(database.postgres.pool())
    .await
    .unwrap();
    let first = storage::expire_due(
        &database.postgres,
        "worker-a",
        "expire-batch-a",
        b"expire-batch-a",
        "org_expire",
        "usr_worker_a",
        2,
    );
    let second = storage::expire_due(
        &database.postgres,
        "worker-b",
        "expire-batch-b",
        b"expire-batch-b",
        "org_expire",
        "usr_worker_b",
        2,
    );
    let (first, second) = tokio::join!(first, second);
    let first = first.unwrap().unwrap();
    let second = second.unwrap().unwrap();
    assert_eq!(first.expired + second.expired, 4);
    let expired: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organization_invitations WHERE organization_id='org_expire' AND state='expired'",
    )
    .fetch_one(database.postgres.pool())
    .await
    .unwrap();
    assert_eq!(expired, 4);
    let activities: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organization_invitation_activity WHERE organization_id='org_expire' AND kind='invitation.expired'",
    )
    .fetch_one(database.postgres.pool())
    .await
    .unwrap();
    assert_eq!(activities, 4);
    let lifecycle_commands: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organization_invitation_commands WHERE organization_id='org_expire' AND kind='notify_lifecycle' AND lifecycle='expired'",
    )
    .fetch_one(database.postgres.pool())
    .await
    .unwrap();
    assert_eq!(lifecycle_commands, 4);
    database.cleanup().await;
}

#[tokio::test]
async fn command_restart_recovery_is_lease_fenced_and_contains_no_plaintext_token() {
    let Some(mut database) = TestDatabase::prepare().await else {
        return;
    };
    let created = create_invitation(
        &database.postgres,
        "org_outbox",
        "outbox@example.com",
        "admin-api",
        "outbox-create-1",
    )
    .await;
    let first_claim = storage::claim_due_commands(&database.postgres, "org_outbox", 1, 30)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(first_claim.kind, "notify_invitation");
    let command_wire: String = sqlx::query(
        "SELECT row_to_json(command_row)::text AS wire FROM (SELECT command_id,organization_id,invitation_id,kind,command_key,token_generation,acceptance_subject,lifecycle,state,attempts,last_error,provider_receipt FROM organization_invitation_commands WHERE command_id=$1) command_row",
    )
    .bind(first_claim.command_id)
    .fetch_one(database.postgres.pool())
    .await
    .unwrap()
    .try_get("wire")
    .unwrap();
    assert!(!command_wire.contains(created.token.as_str()));

    database.restart().await;
    sqlx::query(
        "UPDATE organization_invitation_commands SET lease_until=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE command_id=$1",
    )
    .bind(first_claim.command_id)
    .execute(database.postgres.pool())
    .await
    .unwrap();
    let recovered = storage::claim_due_commands(&database.postgres, "org_outbox", 1, 30)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(recovered.command_id, first_claim.command_id);
    assert_ne!(recovered.lease_token, first_claim.lease_token);
    assert!(
        storage::retry_command(&database.postgres, &first_claim, "stale", 1)
            .await
            .is_err(),
        "a stale worker must not cross the lease fence"
    );
    storage::complete_notification_command(
        &database.postgres,
        &recovered,
        "intent_1",
        "delivery_1",
    )
    .await
    .unwrap();
    let state: String = sqlx::query_scalar(
        "SELECT state FROM organization_invitation_commands WHERE command_id=$1",
    )
    .bind(recovered.command_id)
    .fetch_one(database.postgres.pool())
    .await
    .unwrap();
    assert_eq!(state, "completed");
    let delivery_state: String = sqlx::query_scalar(
        "SELECT delivery_state FROM organization_invitations WHERE invitation_id=$1",
    )
    .bind(created.result.invitation.invitation_id)
    .fetch_one(database.postgres.pool())
    .await
    .unwrap();
    assert_eq!(delivery_state, "queued");
    database.cleanup().await;
}
