use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction, types::Json};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct InvitationView {
    pub(crate) invitation_id: Uuid,
    pub(crate) identifier: String,
    pub(crate) organization_id: String,
    pub(crate) email: String,
    pub(crate) state: String,
    pub(crate) inviter_subject: String,
    pub(crate) accepted_subject: Option<String>,
    #[serde(with = "decimal_i64")]
    pub(crate) revision: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) token_expires_at: OffsetDateTime,
    pub(crate) acceptance_pending: bool,
    pub(crate) delivery_state: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(crate) accepted_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(crate) revoked_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(crate) expired_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct InvitationRecord {
    pub(crate) view: InvitationView,
    pub(crate) email_normalized: String,
    pub(crate) token_hash: Option<String>,
    pub(crate) token_generation: i64,
    pub(crate) acceptance_subject: Option<String>,
    pub(crate) membership_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct StoredTokenResponse {
    invitation: InvitationView,
    #[serde(with = "decimal_i64")]
    token_generation: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TokenOperationResult {
    pub(crate) invitation: InvitationView,
    pub(crate) token_generation: i64,
    pub(crate) disclose_token: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct AcceptedRecord {
    pub(crate) invitation_id: Uuid,
    pub(crate) identifier: String,
    pub(crate) organization_id: String,
    pub(crate) state: String,
    pub(crate) membership_id: String,
    #[serde(with = "decimal_i64")]
    pub(crate) revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ExpiredItem {
    pub(crate) invitation_id: Uuid,
    pub(crate) identifier: String,
    #[serde(with = "decimal_i64")]
    pub(crate) revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ExpireResult {
    pub(crate) expired: i64,
    pub(crate) items: Vec<ExpiredItem>,
    pub(crate) has_more: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct DispatchResult {
    pub(crate) processed: i64,
    pub(crate) completed: i64,
    pub(crate) retry_scheduled: i64,
    pub(crate) permanent_failed: i64,
    pub(crate) has_more: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InvitationCursor {
    pub(crate) created_at: OffsetDateTime,
    pub(crate) invitation_id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct InvitationFilters<'a> {
    pub(crate) organization_id: &'a str,
    pub(crate) state: Option<&'a str>,
    pub(crate) email_normalized: Option<&'a str>,
    pub(crate) cursor: Option<&'a InvitationCursor>,
    pub(crate) limit: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandRecord {
    pub(crate) command_id: Uuid,
    pub(crate) organization_id: String,
    pub(crate) invitation_id: Uuid,
    pub(crate) kind: String,
    pub(crate) command_key: String,
    pub(crate) token_generation: Option<i64>,
    pub(crate) acceptance_subject: Option<String>,
    pub(crate) lifecycle: Option<String>,
    pub(crate) attempts: i32,
    pub(crate) lease_token: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AcceptStart {
    Replay(AcceptedRecord),
    Execute(CommandRecord),
    InProgress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainFailure {
    InvitationNotFound,
    InvitationExists,
    RevisionConflict,
    IdempotencyConflict,
    InvalidTransition,
    TokenInvalid,
    InvitationExpired,
    AcceptanceInProgress,
}

#[derive(Debug, Error)]
pub(crate) enum StorageError {
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("stored Organization Invitation data is invalid: {detail}")]
    InvalidStoredData { detail: String },
    #[error("Organization Invitation command serialization failed")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum MutationReplay<T> {
    New,
    Replay(T),
    InProgress,
}

pub(crate) fn encode_invitation_cursor(
    invitation: &InvitationView,
) -> Result<String, StorageError> {
    let timestamp = invitation.created_at.format(&Rfc3339).map_err(|error| {
        StorageError::InvalidStoredData {
            detail: format!("cursor timestamp cannot be formatted: {error}"),
        }
    })?;
    let payload = serde_json::to_vec(&(timestamp, invitation.invitation_id))?;
    Ok(URL_SAFE_NO_PAD.encode(payload))
}

pub(crate) fn decode_invitation_cursor(value: &str) -> Option<InvitationCursor> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    let (timestamp, invitation_id): (String, Uuid) = serde_json::from_slice(&bytes).ok()?;
    let created_at = OffsetDateTime::parse(&timestamp, &Rfc3339).ok()?;
    Some(InvitationCursor {
        created_at,
        invitation_id,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_invitation(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    invitation_id: Uuid,
    organization_id: &str,
    actor: &str,
    email: &str,
    email_normalized: &str,
    token_hash: &str,
    token_ttl_seconds: i64,
) -> Result<Result<TokenOperationResult, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin invitation creation").await?;
    match begin_mutation::<StoredTokenResponse>(
        &mut transaction,
        caller,
        idempotency_key,
        "invite",
        actor,
        request_hash,
        organization_id,
        None,
    )
    .await?
    {
        Ok(MutationReplay::Replay(replay)) => {
            commit(transaction, "commit invitation creation replay").await?;
            return Ok(Ok(TokenOperationResult {
                invitation: replay.invitation,
                token_generation: replay.token_generation,
                disclose_token: false,
            }));
        }
        Ok(MutationReplay::New) => {}
        Ok(MutationReplay::InProgress) => return Ok(Err(DomainFailure::IdempotencyConflict)),
        Err(failure) => return Ok(Err(failure)),
    }
    // Both fields reject control characters, so this separator is collision-free while
    // remaining valid PostgreSQL UTF-8 text (PostgreSQL text rejects NUL bytes).
    let lock_key = format!("{organization_id}\u{1f}{email_normalized}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("lock pending invitation email", source))?;
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM organization_invitations WHERE organization_id=$1 AND email_normalized=$2 AND state='pending')",
    )
    .bind(organization_id)
    .bind(email_normalized)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("check pending invitation email", source))?;
    if exists {
        return Ok(Err(DomainFailure::InvitationExists));
    }
    let number: i64 = sqlx::query_scalar(
        "INSERT INTO organization_invitation_sequences(organization_id,next_number) VALUES($1,2) ON CONFLICT(organization_id) DO UPDATE SET next_number=organization_invitation_sequences.next_number+1 RETURNING next_number-1",
    )
    .bind(organization_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("allocate invitation identifier", source))?;
    if number <= 0 {
        return Err(StorageError::InvalidStoredData {
            detail: "invitation sequence is not positive".to_owned(),
        });
    }
    let identifier = format!("INV-{number}");
    let row = sqlx::query(
        "INSERT INTO organization_invitations(invitation_id,organization_id,identifier,email,email_normalized,state,inviter_subject,token_hash,token_generation,token_expires_at,revision,delivery_state) VALUES($1,$2,$3,$4,$5,'pending',$6,$7,1,CURRENT_TIMESTAMP+($8::bigint * INTERVAL '1 second'),1,'pending') RETURNING *",
    )
    .bind(invitation_id)
    .bind(organization_id)
    .bind(&identifier)
    .bind(email)
    .bind(email_normalized)
    .bind(actor)
    .bind(token_hash)
    .bind(token_ttl_seconds)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("insert invitation", source))?;
    let record = decode_invitation(&row)?;
    insert_command(
        &mut transaction,
        organization_id,
        invitation_id,
        "notify_invitation",
        &format!("notify:{invitation_id}:1"),
        Some(1),
        None,
        None,
    )
    .await?;
    insert_activity(
        &mut transaction,
        &record.view,
        "invitation.created",
        actor,
        json!({"email_normalized": email_normalized, "token_generation": 1}),
    )
    .await?;
    let stored = StoredTokenResponse {
        invitation: record.view.clone(),
        token_generation: 1,
    };
    complete_mutation(
        &mut transaction,
        caller,
        idempotency_key,
        Some(invitation_id),
        None,
        &stored,
    )
    .await?;
    commit(transaction, "commit invitation creation").await?;
    Ok(Ok(TokenOperationResult {
        invitation: record.view,
        token_generation: 1,
        disclose_token: true,
    }))
}

pub(crate) async fn get_invitation(
    postgres: &OwnedPostgres,
    organization_id: &str,
    invitation_ref: &str,
) -> Result<Option<InvitationRecord>, StorageError> {
    let row = if let Ok(invitation_id) = Uuid::parse_str(invitation_ref) {
        sqlx::query(
            "SELECT * FROM organization_invitations WHERE organization_id=$1 AND invitation_id=$2",
        )
        .bind(organization_id)
        .bind(invitation_id)
        .fetch_optional(postgres.pool())
        .await
    } else {
        sqlx::query(
            "SELECT * FROM organization_invitations WHERE organization_id=$1 AND identifier=$2",
        )
        .bind(organization_id)
        .bind(invitation_ref)
        .fetch_optional(postgres.pool())
        .await
    }
    .map_err(|source| database("read invitation", source))?;
    row.as_ref().map(decode_invitation).transpose()
}

pub(crate) async fn get_invitation_by_id(
    postgres: &OwnedPostgres,
    invitation_id: Uuid,
) -> Result<Option<InvitationRecord>, StorageError> {
    sqlx::query("SELECT * FROM organization_invitations WHERE invitation_id=$1")
        .bind(invitation_id)
        .fetch_optional(postgres.pool())
        .await
        .map_err(|source| database("read invitation by id", source))?
        .as_ref()
        .map(decode_invitation)
        .transpose()
}

pub(crate) async fn list_invitations(
    postgres: &OwnedPostgres,
    filters: &InvitationFilters<'_>,
) -> Result<Vec<InvitationView>, StorageError> {
    let cursor_created_at = filters.cursor.map(|cursor| cursor.created_at);
    let cursor_id = filters.cursor.map(|cursor| cursor.invitation_id);
    let rows = sqlx::query(
        "SELECT * FROM organization_invitations WHERE organization_id=$1 AND ($2::text IS NULL OR state=$2) AND ($3::text IS NULL OR email_normalized=$3) AND ($4::timestamptz IS NULL OR (created_at,invitation_id)<($4,$5)) ORDER BY created_at DESC,invitation_id DESC LIMIT $6",
    )
    .bind(filters.organization_id)
    .bind(filters.state)
    .bind(filters.email_normalized)
    .bind(cursor_created_at)
    .bind(cursor_id)
    .bind(filters.limit)
    .fetch_all(postgres.pool())
    .await
    .map_err(|source| database("list invitations", source))?;
    rows.iter()
        .map(decode_invitation)
        .map(|record| record.map(|record| record.view))
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn resend_invitation(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    invitation_id: Uuid,
    actor: &str,
    expected_revision: i64,
    token_hash: &str,
    token_ttl_seconds: i64,
) -> Result<Result<TokenOperationResult, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin invitation resend").await?;
    match begin_mutation::<StoredTokenResponse>(
        &mut transaction,
        caller,
        idempotency_key,
        "resend",
        actor,
        request_hash,
        organization_id,
        // Bind the resource FK only after acquiring the invitation row lock. If two
        // different mutations bind it here, each transaction first takes a key-share
        // lock through the FK and can deadlock while both upgrade to FOR UPDATE.
        None,
    )
    .await?
    {
        Ok(MutationReplay::Replay(replay)) => {
            commit(transaction, "commit invitation resend replay").await?;
            return Ok(Ok(TokenOperationResult {
                invitation: replay.invitation,
                token_generation: replay.token_generation,
                disclose_token: false,
            }));
        }
        Ok(MutationReplay::New) => {}
        Ok(MutationReplay::InProgress) => return Ok(Err(DomainFailure::IdempotencyConflict)),
        Err(failure) => return Ok(Err(failure)),
    }
    let row = sqlx::query(
        "SELECT * FROM organization_invitations WHERE organization_id=$1 AND invitation_id=$2 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(invitation_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| database("lock invitation for resend", source))?;
    let Some(row) = row else {
        return Ok(Err(DomainFailure::InvitationNotFound));
    };
    let current = decode_invitation(&row)?;
    if current.view.revision != expected_revision {
        return Ok(Err(DomainFailure::RevisionConflict));
    }
    if current.view.state != "pending" {
        return Ok(Err(DomainFailure::InvalidTransition));
    }
    if current.acceptance_subject.is_some() {
        return Ok(Err(DomainFailure::AcceptanceInProgress));
    }
    let generation =
        current
            .token_generation
            .checked_add(1)
            .ok_or_else(|| StorageError::InvalidStoredData {
                detail: "token generation overflowed".to_owned(),
            })?;
    sqlx::query(
        "UPDATE organization_invitation_commands SET state='superseded',updated_at=CURRENT_TIMESTAMP,completed_at=CURRENT_TIMESTAMP,lease_token=NULL,lease_until=NULL WHERE invitation_id=$1 AND kind='notify_invitation' AND state IN ('pending','in_flight')",
    )
    .bind(invitation_id)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("supersede invitation notification", source))?;
    let row = sqlx::query(
        "UPDATE organization_invitations SET token_hash=$3,token_generation=$4,token_expires_at=CURRENT_TIMESTAMP+($5::bigint * INTERVAL '1 second'),revision=revision+1,delivery_state='pending',delivery_intent_id=NULL,delivery_id=NULL,updated_at=CURRENT_TIMESTAMP WHERE organization_id=$1 AND invitation_id=$2 RETURNING *",
    )
    .bind(organization_id)
    .bind(invitation_id)
    .bind(token_hash)
    .bind(generation)
    .bind(token_ttl_seconds)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("rotate invitation token", source))?;
    let record = decode_invitation(&row)?;
    insert_command(
        &mut transaction,
        organization_id,
        invitation_id,
        "notify_invitation",
        &format!("notify:{invitation_id}:{generation}"),
        Some(generation),
        None,
        None,
    )
    .await?;
    insert_activity(
        &mut transaction,
        &record.view,
        "invitation.resent",
        actor,
        json!({"token_generation": generation}),
    )
    .await?;
    let stored = StoredTokenResponse {
        invitation: record.view.clone(),
        token_generation: generation,
    };
    complete_mutation(
        &mut transaction,
        caller,
        idempotency_key,
        Some(invitation_id),
        None,
        &stored,
    )
    .await?;
    commit(transaction, "commit invitation resend").await?;
    Ok(Ok(TokenOperationResult {
        invitation: record.view,
        token_generation: generation,
        disclose_token: true,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn revoke_invitation(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    invitation_id: Uuid,
    actor: &str,
    expected_revision: i64,
    reason: &str,
) -> Result<Result<InvitationView, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin invitation revoke").await?;
    match begin_mutation::<InvitationView>(
        &mut transaction,
        caller,
        idempotency_key,
        "revoke",
        actor,
        request_hash,
        organization_id,
        // Defer the FK until complete_mutation, after the invitation row has
        // serialized competing revision-based mutations.
        None,
    )
    .await?
    {
        Ok(MutationReplay::Replay(replay)) => {
            commit(transaction, "commit invitation revoke replay").await?;
            return Ok(Ok(replay));
        }
        Ok(MutationReplay::New) => {}
        Ok(MutationReplay::InProgress) => return Ok(Err(DomainFailure::IdempotencyConflict)),
        Err(failure) => return Ok(Err(failure)),
    }
    let row = sqlx::query(
        "SELECT * FROM organization_invitations WHERE organization_id=$1 AND invitation_id=$2 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(invitation_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| database("lock invitation for revoke", source))?;
    let Some(row) = row else {
        return Ok(Err(DomainFailure::InvitationNotFound));
    };
    let current = decode_invitation(&row)?;
    if current.view.revision != expected_revision {
        return Ok(Err(DomainFailure::RevisionConflict));
    }
    if current.view.state != "pending" {
        return Ok(Err(DomainFailure::InvalidTransition));
    }
    if current.acceptance_subject.is_some() {
        return Ok(Err(DomainFailure::AcceptanceInProgress));
    }
    sqlx::query(
        "UPDATE organization_invitation_commands SET state='superseded',updated_at=CURRENT_TIMESTAMP,completed_at=CURRENT_TIMESTAMP,lease_token=NULL,lease_until=NULL WHERE invitation_id=$1 AND kind='notify_invitation' AND state IN ('pending','in_flight')",
    )
    .bind(invitation_id)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("supersede revoked invitation notification", source))?;
    let row = sqlx::query(
        "UPDATE organization_invitations SET state='revoked',token_hash=NULL,revision=revision+1,delivery_state=CASE WHEN delivery_state='pending' THEN 'superseded' ELSE delivery_state END,revoke_reason=$3,revoked_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE organization_id=$1 AND invitation_id=$2 RETURNING *",
    )
    .bind(organization_id)
    .bind(invitation_id)
    .bind(reason)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("revoke invitation", source))?;
    let record = decode_invitation(&row)?;
    insert_command(
        &mut transaction,
        organization_id,
        invitation_id,
        "notify_lifecycle",
        &format!("lifecycle:{invitation_id}:revoked"),
        None,
        None,
        Some("revoked"),
    )
    .await?;
    insert_activity(
        &mut transaction,
        &record.view,
        "invitation.revoked",
        actor,
        json!({"reason": reason}),
    )
    .await?;
    complete_mutation(
        &mut transaction,
        caller,
        idempotency_key,
        Some(invitation_id),
        None,
        &record.view,
    )
    .await?;
    commit(transaction, "commit invitation revoke").await?;
    Ok(Ok(record.view))
}

pub(crate) async fn lookup_accept_replay(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    actor: &str,
    request_hash: &[u8],
) -> Result<Result<Option<AcceptStart>, DomainFailure>, StorageError> {
    let row = sqlx::query(
        "SELECT operation,actor_subject,request_hash,status,response FROM organization_invitation_mutations WHERE caller_instance=$1 AND idempotency_key=$2",
    )
    .bind(caller)
    .bind(idempotency_key)
    .fetch_optional(postgres.pool())
    .await
    .map_err(|source| database("read acceptance replay", source))?;
    let Some(row) = row else {
        return Ok(Ok(None));
    };
    let operation: String = row
        .try_get("operation")
        .map_err(|source| database("decode acceptance replay operation", source))?;
    let stored_actor: String = row
        .try_get("actor_subject")
        .map_err(|source| database("decode acceptance replay actor", source))?;
    let stored_hash: Vec<u8> = row
        .try_get("request_hash")
        .map_err(|source| database("decode acceptance replay hash", source))?;
    if operation != "accept" || stored_actor != actor || stored_hash != request_hash {
        return Ok(Err(DomainFailure::IdempotencyConflict));
    }
    let response: Option<Json<Value>> = row
        .try_get("response")
        .map_err(|source| database("decode acceptance replay response", source))?;
    match response {
        Some(Json(value)) => Ok(Ok(Some(AcceptStart::Replay(serde_json::from_value(
            value,
        )?)))),
        None => Ok(Ok(Some(AcceptStart::InProgress))),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn begin_accept(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    invitation_id: Uuid,
    actor: &str,
    expected_revision: i64,
    observed_generation: i64,
    observed_token_hash: &str,
    lease_seconds: i64,
) -> Result<Result<AcceptStart, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin invitation acceptance").await?;
    match begin_mutation::<AcceptedRecord>(
        &mut transaction,
        caller,
        idempotency_key,
        "accept",
        actor,
        request_hash,
        "pending-resource-lookup",
        // The acceptance transaction binds the resource below, after its row lock.
        // Deferring the FK prevents the same lock-upgrade deadlock as resend/revoke.
        None,
    )
    .await?
    {
        Ok(MutationReplay::Replay(replay)) => {
            commit(transaction, "commit invitation acceptance replay").await?;
            return Ok(Ok(AcceptStart::Replay(replay)));
        }
        Ok(MutationReplay::InProgress) => {
            commit(
                transaction,
                "commit invitation acceptance in-progress replay",
            )
            .await?;
            return Ok(Ok(AcceptStart::InProgress));
        }
        Ok(MutationReplay::New) => {}
        Err(failure) => return Ok(Err(failure)),
    }
    let row = sqlx::query(
        "SELECT *, token_expires_at<=CURRENT_TIMESTAMP AS token_due FROM organization_invitations WHERE invitation_id=$1 FOR UPDATE",
    )
    .bind(invitation_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| database("lock invitation for acceptance", source))?;
    let Some(row) = row else {
        return Ok(Err(DomainFailure::InvitationNotFound));
    };
    let current = decode_invitation(&row)?;
    let token_due: bool = row
        .try_get("token_due")
        .map_err(|source| database("decode invitation token deadline", source))?;
    if current.view.revision != expected_revision {
        return Ok(Err(DomainFailure::RevisionConflict));
    }
    if current.view.state != "pending" {
        return Ok(Err(DomainFailure::InvalidTransition));
    }
    if current.acceptance_subject.is_some() {
        return Ok(Err(DomainFailure::AcceptanceInProgress));
    }
    if token_due {
        sqlx::query(
            "DELETE FROM organization_invitation_mutations WHERE caller_instance=$1 AND idempotency_key=$2",
        )
        .bind(caller)
        .bind(idempotency_key)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("release expired acceptance mutation", source))?;
        let expired = expire_locked_invitation(&mut transaction, &current).await?;
        insert_activity(
            &mut transaction,
            &expired.view,
            "invitation.expired",
            "system:accept",
            json!({"reason": "token_deadline"}),
        )
        .await?;
        commit(transaction, "commit expiration discovered by acceptance").await?;
        return Ok(Err(DomainFailure::InvitationExpired));
    }
    if current.token_generation != observed_generation
        || current.token_hash.as_deref() != Some(observed_token_hash)
    {
        return Ok(Err(DomainFailure::TokenInvalid));
    }
    let row = sqlx::query(
        "UPDATE organization_invitations SET acceptance_subject=$2,token_hash=NULL,token_consumed_at=CURRENT_TIMESTAMP,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE invitation_id=$1 RETURNING *",
    )
    .bind(invitation_id)
    .bind(actor)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("consume invitation token", source))?;
    let accepted_pending = decode_invitation(&row)?;
    let command_id = insert_command(
        &mut transaction,
        &current.view.organization_id,
        invitation_id,
        "add_member",
        &format!("membership:{invitation_id}"),
        None,
        Some(actor),
        None,
    )
    .await?;
    let lease_token = Uuid::new_v4();
    sqlx::query(
        "UPDATE organization_invitation_commands SET state='in_flight',attempts=attempts+1,lease_token=$2,lease_until=CURRENT_TIMESTAMP+($3::bigint * INTERVAL '1 second'),updated_at=CURRENT_TIMESTAMP WHERE command_id=$1",
    )
    .bind(command_id)
    .bind(lease_token)
    .bind(lease_seconds)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("claim membership command for acceptance", source))?;
    sqlx::query(
        "UPDATE organization_invitation_mutations SET organization_id=$3,invitation_id=$4,side_effect_command_id=$5 WHERE caller_instance=$1 AND idempotency_key=$2",
    )
    .bind(caller)
    .bind(idempotency_key)
    .bind(&current.view.organization_id)
    .bind(invitation_id)
    .bind(command_id)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("bind acceptance mutation to command", source))?;
    insert_activity(
        &mut transaction,
        &accepted_pending.view,
        "invitation.acceptance_started",
        actor,
        json!({"command_id": command_id}),
    )
    .await?;
    commit(transaction, "commit invitation acceptance start").await?;
    Ok(Ok(AcceptStart::Execute(CommandRecord {
        command_id,
        organization_id: current.view.organization_id,
        invitation_id,
        kind: "add_member".to_owned(),
        command_key: format!("membership:{invitation_id}"),
        token_generation: None,
        acceptance_subject: Some(actor.to_owned()),
        lifecycle: None,
        attempts: 1,
        lease_token,
    })))
}

pub(crate) async fn complete_accept(
    postgres: &OwnedPostgres,
    command: &CommandRecord,
    membership_id: &str,
    provider_revision: &str,
) -> Result<AcceptedRecord, StorageError> {
    let mut transaction = begin(postgres, "begin acceptance completion").await?;
    let row = sqlx::query(
        "SELECT state,lease_token FROM organization_invitation_commands WHERE command_id=$1 FOR UPDATE",
    )
    .bind(command.command_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("lock membership command completion", source))?;
    let state: String = row
        .try_get("state")
        .map_err(|source| database("decode membership command state", source))?;
    if state == "completed" {
        let invitation = lock_invitation(&mut transaction, command.invitation_id).await?;
        let accepted = accepted_record(&invitation)?;
        commit(transaction, "commit acceptance completion replay").await?;
        return Ok(accepted);
    }
    let lease_token: Option<Uuid> = row
        .try_get("lease_token")
        .map_err(|source| database("decode membership command lease", source))?;
    if state != "in_flight" || lease_token != Some(command.lease_token) {
        return Err(StorageError::InvalidStoredData {
            detail: "membership command completion crossed its lease fence".to_owned(),
        });
    }
    let invitation = lock_invitation(&mut transaction, command.invitation_id).await?;
    if invitation.view.state != "pending"
        || invitation.acceptance_subject.as_deref() != command.acceptance_subject.as_deref()
    {
        return Err(StorageError::InvalidStoredData {
            detail: "membership command no longer matches its invitation".to_owned(),
        });
    }
    let row = sqlx::query(
        "UPDATE organization_invitations SET state='accepted',membership_id=$2,revision=revision+1,accepted_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE invitation_id=$1 RETURNING *",
    )
    .bind(command.invitation_id)
    .bind(membership_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("complete invitation acceptance", source))?;
    let completed = decode_invitation(&row)?;
    let accepted = accepted_record(&completed)?;
    let receipt = json!({"membership_id": membership_id, "membership_revision": provider_revision});
    finish_command_row(
        &mut transaction,
        command.command_id,
        command.lease_token,
        "completed",
        Some(receipt),
        None,
    )
    .await?;
    insert_command(
        &mut transaction,
        &completed.view.organization_id,
        completed.view.invitation_id,
        "notify_lifecycle",
        &format!("lifecycle:{}:accepted", completed.view.invitation_id),
        None,
        None,
        Some("accepted"),
    )
    .await?;
    insert_activity(
        &mut transaction,
        &completed.view,
        "invitation.accepted",
        completed
            .acceptance_subject
            .as_deref()
            .unwrap_or("system:membership"),
        json!({"membership_id": membership_id, "provider_revision": provider_revision}),
    )
    .await?;
    let response = Json(serde_json::to_value(&accepted)?);
    sqlx::query(
        "UPDATE organization_invitation_mutations SET status='completed',response=$2 WHERE side_effect_command_id=$1 AND operation='accept' AND status='started'",
    )
    .bind(command.command_id)
    .bind(response)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("complete acceptance mutation", source))?;
    commit(transaction, "commit acceptance completion").await?;
    Ok(accepted)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn expire_due(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    actor: &str,
    limit: i64,
) -> Result<Result<ExpireResult, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin due invitation expiry").await?;
    match begin_mutation::<ExpireResult>(
        &mut transaction,
        caller,
        idempotency_key,
        "expire_due",
        actor,
        request_hash,
        organization_id,
        None,
    )
    .await?
    {
        Ok(MutationReplay::Replay(replay)) => {
            commit(transaction, "commit due invitation expiry replay").await?;
            return Ok(Ok(replay));
        }
        Ok(MutationReplay::New) => {}
        Ok(MutationReplay::InProgress) => return Ok(Err(DomainFailure::IdempotencyConflict)),
        Err(failure) => return Ok(Err(failure)),
    }
    let rows = sqlx::query(
        "SELECT * FROM organization_invitations WHERE organization_id=$1 AND state='pending' AND acceptance_subject IS NULL AND token_expires_at<=CURRENT_TIMESTAMP ORDER BY token_expires_at ASC,invitation_id ASC FOR UPDATE SKIP LOCKED LIMIT $2",
    )
    .bind(organization_id)
    .bind(limit)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|source| database("claim due invitations for expiry", source))?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let current = decode_invitation(row)?;
        let expired = expire_locked_invitation(&mut transaction, &current).await?;
        insert_activity(
            &mut transaction,
            &expired.view,
            "invitation.expired",
            actor,
            json!({"reason": "token_deadline"}),
        )
        .await?;
        items.push(ExpiredItem {
            invitation_id: expired.view.invitation_id,
            identifier: expired.view.identifier,
            revision: expired.view.revision,
        });
    }
    let has_more = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM organization_invitations WHERE organization_id=$1 AND state='pending' AND acceptance_subject IS NULL AND token_expires_at<=CURRENT_TIMESTAMP)",
    )
    .bind(organization_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("check remaining due invitations", source))?;
    let result = ExpireResult {
        expired: i64::try_from(items.len()).map_err(|_| StorageError::InvalidStoredData {
            detail: "expired invitation count overflowed".to_owned(),
        })?,
        items,
        has_more,
    };
    complete_mutation(
        &mut transaction,
        caller,
        idempotency_key,
        None,
        None,
        &result,
    )
    .await?;
    commit(transaction, "commit due invitation expiry").await?;
    Ok(Ok(result))
}

pub(crate) async fn begin_dispatch_batch(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    actor: &str,
) -> Result<Result<Option<DispatchResult>, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin invitation command dispatch batch").await?;
    let result = match begin_mutation::<DispatchResult>(
        &mut transaction,
        caller,
        idempotency_key,
        "dispatch_due",
        actor,
        request_hash,
        organization_id,
        None,
    )
    .await?
    {
        Ok(MutationReplay::Replay(replay)) => Ok(Some(replay)),
        Ok(MutationReplay::New) => Ok(None),
        Ok(MutationReplay::InProgress) | Err(DomainFailure::IdempotencyConflict) => {
            Err(DomainFailure::IdempotencyConflict)
        }
        Err(failure) => Err(failure),
    };
    commit(
        transaction,
        "commit invitation command dispatch reservation",
    )
    .await?;
    Ok(result)
}

pub(crate) async fn complete_dispatch_batch(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    result: &DispatchResult,
) -> Result<(), StorageError> {
    let response = Json(serde_json::to_value(result)?);
    sqlx::query(
        "UPDATE organization_invitation_mutations SET status='completed',response=$3 WHERE caller_instance=$1 AND idempotency_key=$2 AND operation='dispatch_due' AND status='started'",
    )
    .bind(caller)
    .bind(idempotency_key)
    .bind(response)
    .execute(postgres.pool())
    .await
    .and_then(|result| {
        if result.rows_affected() == 1 {
            Ok(result)
        } else {
            Err(sqlx::Error::RowNotFound)
        }
    })
    .map(|_| ())
    .map_err(|source| database("complete invitation command dispatch batch", source))
}

pub(crate) async fn claim_due_commands(
    postgres: &OwnedPostgres,
    organization_id: &str,
    limit: i64,
    lease_seconds: i64,
) -> Result<Vec<CommandRecord>, StorageError> {
    let mut transaction = begin(postgres, "begin invitation command claim").await?;
    let ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT command_id FROM organization_invitation_commands WHERE organization_id=$1 AND ((state='pending' AND available_at<=CURRENT_TIMESTAMP) OR (state='in_flight' AND lease_until<CURRENT_TIMESTAMP)) ORDER BY available_at ASC,command_id ASC FOR UPDATE SKIP LOCKED LIMIT $2",
    )
    .bind(organization_id)
    .bind(limit)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|source| database("claim due invitation commands", source))?;
    let mut commands = Vec::with_capacity(ids.len());
    for command_id in ids {
        let lease_token = Uuid::new_v4();
        let row = sqlx::query(
            "UPDATE organization_invitation_commands SET state='in_flight',attempts=attempts+1,lease_token=$2,lease_until=CURRENT_TIMESTAMP+($3::bigint * INTERVAL '1 second'),updated_at=CURRENT_TIMESTAMP WHERE command_id=$1 RETURNING *",
        )
        .bind(command_id)
        .bind(lease_token)
        .bind(lease_seconds)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|source| database("lease invitation command", source))?;
        commands.push(decode_command(&row)?);
    }
    commit(transaction, "commit invitation command claim").await?;
    Ok(commands)
}

pub(crate) async fn has_due_commands(
    postgres: &OwnedPostgres,
    organization_id: &str,
) -> Result<bool, StorageError> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organization_invitation_commands WHERE organization_id=$1 AND ((state='pending' AND available_at<=CURRENT_TIMESTAMP) OR (state='in_flight' AND lease_until<CURRENT_TIMESTAMP)))",
    )
    .bind(organization_id)
    .fetch_one(postgres.pool())
    .await
    .map_err(|source| database("check due invitation commands", source))
}

pub(crate) async fn command_matches_invitation(
    postgres: &OwnedPostgres,
    command: &CommandRecord,
) -> Result<Option<InvitationRecord>, StorageError> {
    let invitation = get_invitation_by_id(postgres, command.invitation_id).await?;
    Ok(invitation.filter(|invitation| match command.kind.as_str() {
        "notify_invitation" => {
            invitation.view.state == "pending"
                && invitation.token_hash.is_some()
                && command.token_generation == Some(invitation.token_generation)
        }
        "notify_lifecycle" => command.lifecycle.as_deref() == Some(invitation.view.state.as_str()),
        "add_member" => {
            invitation.view.state == "pending"
                && invitation.acceptance_subject.as_deref() == command.acceptance_subject.as_deref()
        }
        _ => false,
    }))
}

pub(crate) async fn complete_notification_command(
    postgres: &OwnedPostgres,
    command: &CommandRecord,
    intent_id: &str,
    delivery_id: &str,
) -> Result<(), StorageError> {
    let mut transaction = begin(postgres, "begin invitation notification completion").await?;
    let receipt = json!({"intent_id": intent_id, "delivery_id": delivery_id});
    finish_command_row(
        &mut transaction,
        command.command_id,
        command.lease_token,
        "completed",
        Some(receipt),
        None,
    )
    .await?;
    sqlx::query(
        "UPDATE organization_invitations SET delivery_state='queued',delivery_intent_id=$3,delivery_id=$4,updated_at=CURRENT_TIMESTAMP WHERE invitation_id=$1 AND state='pending' AND token_generation=$2",
    )
    .bind(command.invitation_id)
    .bind(command.token_generation)
    .bind(intent_id)
    .bind(delivery_id)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("record invitation notification receipt", source))?;
    commit(transaction, "commit invitation notification completion").await
}

pub(crate) async fn complete_lifecycle_command(
    postgres: &OwnedPostgres,
    command: &CommandRecord,
    recorded: bool,
) -> Result<(), StorageError> {
    let mut transaction = begin(postgres, "begin invitation lifecycle completion").await?;
    finish_command_row(
        &mut transaction,
        command.command_id,
        command.lease_token,
        "completed",
        Some(json!({"recorded": recorded})),
        None,
    )
    .await?;
    commit(transaction, "commit invitation lifecycle completion").await
}

pub(crate) async fn retry_command(
    postgres: &OwnedPostgres,
    command: &CommandRecord,
    error_code: &str,
    retry_after_seconds: i64,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE organization_invitation_commands SET state='pending',available_at=CURRENT_TIMESTAMP+($3::bigint * INTERVAL '1 second'),lease_token=NULL,lease_until=NULL,last_error=$4,updated_at=CURRENT_TIMESTAMP WHERE command_id=$1 AND state='in_flight' AND lease_token=$2",
    )
    .bind(command.command_id)
    .bind(command.lease_token)
    .bind(retry_after_seconds)
    .bind(error_code)
    .execute(postgres.pool())
    .await
    .and_then(|result| {
        if result.rows_affected() == 1 {
            Ok(result)
        } else {
            Err(sqlx::Error::RowNotFound)
        }
    })
    .map(|_| ())
    .map_err(|source| database("schedule invitation command retry", source))
}

pub(crate) async fn fail_command(
    postgres: &OwnedPostgres,
    command: &CommandRecord,
    error_code: &str,
) -> Result<(), StorageError> {
    let mut transaction = begin(postgres, "begin invitation command failure").await?;
    finish_command_row(
        &mut transaction,
        command.command_id,
        command.lease_token,
        "failed",
        None,
        Some(error_code),
    )
    .await?;
    if command.kind == "notify_invitation" {
        sqlx::query(
            "UPDATE organization_invitations SET delivery_state='failed',updated_at=CURRENT_TIMESTAMP WHERE invitation_id=$1 AND state='pending' AND token_generation=$2",
        )
        .bind(command.invitation_id)
        .bind(command.token_generation)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("record invitation notification failure", source))?;
    } else if command.kind == "add_member" {
        let invitation = lock_invitation(&mut transaction, command.invitation_id).await?;
        if invitation.view.state == "pending"
            && invitation.acceptance_subject.as_deref() == command.acceptance_subject.as_deref()
        {
            let expired = expire_locked_invitation(&mut transaction, &invitation).await?;
            insert_activity(
                &mut transaction,
                &expired.view,
                "invitation.acceptance_failed",
                "system:membership-failure",
                json!({"error_code": error_code}),
            )
            .await?;
            sqlx::query(
                "DELETE FROM organization_invitation_mutations WHERE side_effect_command_id=$1 AND operation='accept' AND status='started'",
            )
            .bind(command.command_id)
            .execute(&mut *transaction)
            .await
            .map_err(|source| database("release permanently failed acceptance mutation", source))?;
        }
    }
    commit(transaction, "commit invitation command failure").await
}

pub(crate) async fn supersede_command(
    postgres: &OwnedPostgres,
    command: &CommandRecord,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE organization_invitation_commands SET state='superseded',lease_token=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP,completed_at=CURRENT_TIMESTAMP WHERE command_id=$1 AND state='in_flight' AND lease_token=$2",
    )
    .bind(command.command_id)
    .bind(command.lease_token)
    .execute(postgres.pool())
    .await
    .and_then(|result| {
        if result.rows_affected() == 1 {
            Ok(result)
        } else {
            Err(sqlx::Error::RowNotFound)
        }
    })
    .map(|_| ())
    .map_err(|source| database("supersede invitation command", source))
}

#[allow(clippy::too_many_arguments)]
async fn begin_mutation<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    idempotency_key: &str,
    operation: &str,
    actor: &str,
    request_hash: &[u8],
    organization_id: &str,
    invitation_id: Option<Uuid>,
) -> Result<Result<MutationReplay<T>, DomainFailure>, StorageError> {
    let inserted = sqlx::query(
        "INSERT INTO organization_invitation_mutations(caller_instance,idempotency_key,operation,actor_subject,request_hash,organization_id,invitation_id,status) VALUES($1,$2,$3,$4,$5,$6,$7,'started') ON CONFLICT(caller_instance,idempotency_key) DO NOTHING",
    )
    .bind(caller)
    .bind(idempotency_key)
    .bind(operation)
    .bind(actor)
    .bind(request_hash)
    .bind(organization_id)
    .bind(invitation_id)
    .execute(&mut **transaction)
    .await
    .map_err(|source| database("reserve invitation mutation", source))?
    .rows_affected()
        == 1;
    if inserted {
        return Ok(Ok(MutationReplay::New));
    }
    let row = sqlx::query(
        "SELECT operation,actor_subject,request_hash,status,response FROM organization_invitation_mutations WHERE caller_instance=$1 AND idempotency_key=$2 FOR UPDATE",
    )
    .bind(caller)
    .bind(idempotency_key)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|source| database("read invitation mutation replay", source))?;
    let stored_operation: String = row
        .try_get("operation")
        .map_err(|source| database("decode invitation mutation operation", source))?;
    let stored_actor: String = row
        .try_get("actor_subject")
        .map_err(|source| database("decode invitation mutation actor", source))?;
    let stored_hash: Vec<u8> = row
        .try_get("request_hash")
        .map_err(|source| database("decode invitation mutation hash", source))?;
    if stored_operation != operation || stored_actor != actor || stored_hash != request_hash {
        return Ok(Err(DomainFailure::IdempotencyConflict));
    }
    let response: Option<Json<Value>> = row
        .try_get("response")
        .map_err(|source| database("decode invitation mutation response", source))?;
    if let Some(Json(response)) = response {
        return Ok(Ok(MutationReplay::Replay(serde_json::from_value(
            response,
        )?)));
    }
    Ok(Ok(MutationReplay::InProgress))
}

async fn complete_mutation<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    idempotency_key: &str,
    invitation_id: Option<Uuid>,
    side_effect_command_id: Option<Uuid>,
    response: &T,
) -> Result<(), StorageError> {
    let response = Json(serde_json::to_value(response)?);
    sqlx::query(
        "UPDATE organization_invitation_mutations SET invitation_id=COALESCE($3,invitation_id),side_effect_command_id=$4,status='completed',response=$5 WHERE caller_instance=$1 AND idempotency_key=$2 AND status='started'",
    )
    .bind(caller)
    .bind(idempotency_key)
    .bind(invitation_id)
    .bind(side_effect_command_id)
    .bind(response)
    .execute(&mut **transaction)
    .await
    .and_then(|result| {
        if result.rows_affected() == 1 {
            Ok(result)
        } else {
            Err(sqlx::Error::RowNotFound)
        }
    })
    .map(|_| ())
    .map_err(|source| database("complete invitation mutation", source))
}

#[allow(clippy::too_many_arguments)]
async fn insert_command(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    invitation_id: Uuid,
    kind: &str,
    command_key: &str,
    token_generation: Option<i64>,
    acceptance_subject: Option<&str>,
    lifecycle: Option<&str>,
) -> Result<Uuid, StorageError> {
    let command_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO organization_invitation_commands(command_id,organization_id,invitation_id,kind,command_key,token_generation,acceptance_subject,lifecycle,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending') ON CONFLICT(command_key) DO NOTHING",
    )
    .bind(command_id)
    .bind(organization_id)
    .bind(invitation_id)
    .bind(kind)
    .bind(command_key)
    .bind(token_generation)
    .bind(acceptance_subject)
    .bind(lifecycle)
    .execute(&mut **transaction)
    .await
    .map_err(|source| database("insert invitation command", source))?;
    sqlx::query_scalar(
        "SELECT command_id FROM organization_invitation_commands WHERE command_key=$1",
    )
    .bind(command_key)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|source| database("read invitation command id", source))
}

async fn finish_command_row(
    transaction: &mut Transaction<'_, Postgres>,
    command_id: Uuid,
    lease_token: Uuid,
    state: &str,
    receipt: Option<Value>,
    error_code: Option<&str>,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE organization_invitation_commands SET state=$3,provider_receipt=$4,last_error=$5,lease_token=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP,completed_at=CURRENT_TIMESTAMP WHERE command_id=$1 AND state='in_flight' AND lease_token=$2",
    )
    .bind(command_id)
    .bind(lease_token)
    .bind(state)
    .bind(receipt.map(Json))
    .bind(error_code)
    .execute(&mut **transaction)
    .await
    .and_then(|result| {
        if result.rows_affected() == 1 {
            Ok(result)
        } else {
            Err(sqlx::Error::RowNotFound)
        }
    })
    .map(|_| ())
    .map_err(|source| database("finish invitation command", source))
}

async fn expire_locked_invitation(
    transaction: &mut Transaction<'_, Postgres>,
    current: &InvitationRecord,
) -> Result<InvitationRecord, StorageError> {
    sqlx::query(
        "UPDATE organization_invitation_commands SET state='superseded',lease_token=NULL,lease_until=NULL,updated_at=CURRENT_TIMESTAMP,completed_at=CURRENT_TIMESTAMP WHERE invitation_id=$1 AND kind='notify_invitation' AND state IN ('pending','in_flight')",
    )
    .bind(current.view.invitation_id)
    .execute(&mut **transaction)
    .await
    .map_err(|source| database("supersede expired invitation notification", source))?;
    let row = sqlx::query(
        "UPDATE organization_invitations SET state='expired',token_hash=NULL,revision=revision+1,delivery_state=CASE WHEN delivery_state='pending' THEN 'superseded' ELSE delivery_state END,expired_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE invitation_id=$1 AND state='pending' RETURNING *",
    )
    .bind(current.view.invitation_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|source| database("expire invitation", source))?;
    let expired = decode_invitation(&row)?;
    insert_command(
        transaction,
        &expired.view.organization_id,
        expired.view.invitation_id,
        "notify_lifecycle",
        &format!("lifecycle:{}:expired", expired.view.invitation_id),
        None,
        None,
        Some("expired"),
    )
    .await?;
    Ok(expired)
}

async fn lock_invitation(
    transaction: &mut Transaction<'_, Postgres>,
    invitation_id: Uuid,
) -> Result<InvitationRecord, StorageError> {
    let row =
        sqlx::query("SELECT * FROM organization_invitations WHERE invitation_id=$1 FOR UPDATE")
            .bind(invitation_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|source| database("lock invitation", source))?;
    decode_invitation(&row)
}

fn accepted_record(invitation: &InvitationRecord) -> Result<AcceptedRecord, StorageError> {
    if invitation.view.state != "accepted" {
        return Err(StorageError::InvalidStoredData {
            detail: "completed membership command points to a non-accepted invitation".to_owned(),
        });
    }
    let membership_id =
        invitation
            .membership_id
            .clone()
            .ok_or_else(|| StorageError::InvalidStoredData {
                detail: "accepted invitation has no membership id".to_owned(),
            })?;
    Ok(AcceptedRecord {
        invitation_id: invitation.view.invitation_id,
        identifier: invitation.view.identifier.clone(),
        organization_id: invitation.view.organization_id.clone(),
        state: invitation.view.state.clone(),
        membership_id,
        revision: invitation.view.revision,
    })
}

async fn insert_activity(
    transaction: &mut Transaction<'_, Postgres>,
    invitation: &InvitationView,
    kind: &str,
    actor: &str,
    evidence: Value,
) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO organization_invitation_activity(activity_id,organization_id,invitation_id,kind,actor_subject,invitation_revision,evidence) VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(Uuid::new_v4())
    .bind(&invitation.organization_id)
    .bind(invitation.invitation_id)
    .bind(kind)
    .bind(actor)
    .bind(invitation.revision)
    .bind(Json(evidence))
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(|source| database("insert invitation activity", source))
}

fn decode_invitation(row: &sqlx::postgres::PgRow) -> Result<InvitationRecord, StorageError> {
    let state: String = row
        .try_get("state")
        .map_err(|source| database("decode invitation state", source))?;
    if !matches!(
        state.as_str(),
        "pending" | "accepted" | "revoked" | "expired"
    ) {
        return Err(StorageError::InvalidStoredData {
            detail: format!("unknown invitation state `{state}`"),
        });
    }
    let delivery_state: String = row
        .try_get("delivery_state")
        .map_err(|source| database("decode invitation delivery state", source))?;
    if !matches!(
        delivery_state.as_str(),
        "pending" | "queued" | "failed" | "superseded"
    ) {
        return Err(StorageError::InvalidStoredData {
            detail: format!("unknown invitation delivery state `{delivery_state}`"),
        });
    }
    let invitation_id = row
        .try_get("invitation_id")
        .map_err(|source| database("decode invitation id", source))?;
    let organization_id = row
        .try_get("organization_id")
        .map_err(|source| database("decode invitation organization", source))?;
    let acceptance_subject: Option<String> = row
        .try_get("acceptance_subject")
        .map_err(|source| database("decode invitation acceptance subject", source))?;
    Ok(InvitationRecord {
        view: InvitationView {
            invitation_id,
            identifier: row
                .try_get("identifier")
                .map_err(|source| database("decode invitation identifier", source))?,
            organization_id,
            email: row
                .try_get("email")
                .map_err(|source| database("decode invitation email", source))?,
            state,
            inviter_subject: row
                .try_get("inviter_subject")
                .map_err(|source| database("decode invitation inviter", source))?,
            accepted_subject: if row
                .try_get::<String, _>("state")
                .map_err(|source| database("decode invitation accepted state", source))?
                == "accepted"
            {
                acceptance_subject.clone()
            } else {
                None
            },
            revision: row
                .try_get("revision")
                .map_err(|source| database("decode invitation revision", source))?,
            token_expires_at: row
                .try_get("token_expires_at")
                .map_err(|source| database("decode invitation token expiry", source))?,
            acceptance_pending: acceptance_subject.is_some()
                && row
                    .try_get::<String, _>("state")
                    .map_err(|source| database("decode invitation pending state", source))?
                    == "pending",
            delivery_state,
            created_at: row
                .try_get("created_at")
                .map_err(|source| database("decode invitation created time", source))?,
            updated_at: row
                .try_get("updated_at")
                .map_err(|source| database("decode invitation updated time", source))?,
            accepted_at: row
                .try_get("accepted_at")
                .map_err(|source| database("decode invitation accepted time", source))?,
            revoked_at: row
                .try_get("revoked_at")
                .map_err(|source| database("decode invitation revoked time", source))?,
            expired_at: row
                .try_get("expired_at")
                .map_err(|source| database("decode invitation expired time", source))?,
        },
        email_normalized: row
            .try_get("email_normalized")
            .map_err(|source| database("decode normalized invitation email", source))?,
        token_hash: row
            .try_get("token_hash")
            .map_err(|source| database("decode invitation token hash", source))?,
        token_generation: row
            .try_get("token_generation")
            .map_err(|source| database("decode invitation token generation", source))?,
        acceptance_subject,
        membership_id: row
            .try_get("membership_id")
            .map_err(|source| database("decode invitation membership", source))?,
    })
}

fn decode_command(row: &sqlx::postgres::PgRow) -> Result<CommandRecord, StorageError> {
    let lease_token = row
        .try_get::<Option<Uuid>, _>("lease_token")
        .map_err(|source| database("decode invitation command lease", source))?
        .ok_or_else(|| StorageError::InvalidStoredData {
            detail: "claimed invitation command has no lease token".to_owned(),
        })?;
    Ok(CommandRecord {
        command_id: row
            .try_get("command_id")
            .map_err(|source| database("decode invitation command id", source))?,
        organization_id: row
            .try_get("organization_id")
            .map_err(|source| database("decode invitation command organization", source))?,
        invitation_id: row
            .try_get("invitation_id")
            .map_err(|source| database("decode invitation command resource", source))?,
        kind: row
            .try_get("kind")
            .map_err(|source| database("decode invitation command kind", source))?,
        command_key: row
            .try_get("command_key")
            .map_err(|source| database("decode invitation command key", source))?,
        token_generation: row
            .try_get("token_generation")
            .map_err(|source| database("decode invitation command generation", source))?,
        acceptance_subject: row
            .try_get("acceptance_subject")
            .map_err(|source| database("decode invitation command subject", source))?,
        lifecycle: row
            .try_get("lifecycle")
            .map_err(|source| database("decode invitation command lifecycle", source))?,
        attempts: row
            .try_get("attempts")
            .map_err(|source| database("decode invitation command attempts", source))?,
        lease_token,
    })
}

async fn begin<'a>(
    postgres: &'a OwnedPostgres,
    operation: &'static str,
) -> Result<Transaction<'a, Postgres>, StorageError> {
    postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database(operation, source))
}

async fn commit(
    transaction: Transaction<'_, Postgres>,
    operation: &'static str,
) -> Result<(), StorageError> {
    transaction
        .commit()
        .await
        .map_err(|source| database(operation, source))
}

const fn database(operation: &'static str, source: sqlx::Error) -> StorageError {
    StorageError::Database { operation, source }
}

mod decimal_i64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(super) fn serialize<S>(value: &i64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<i64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| D::Error::custom("expected a positive decimal i64 string"))
    }
}
