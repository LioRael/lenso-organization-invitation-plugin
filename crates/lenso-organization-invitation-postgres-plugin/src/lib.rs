//! PostgreSQL-backed Organization Invitation lifecycle with durable cross-Plugin commands.

mod operator;
#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
mod schema;
mod storage;
mod token;

use std::{cell::RefCell, collections::BTreeSet, fmt, rc::Rc, time::Duration};

use lenso::prelude::*;
use lenso_auth_sdk::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, AssertionClock, TypedActor,
};
use lenso_capability_access_control as access;
use lenso_capability_access_control::{
    AccessControlInvocationError, CheckPermissionRequest, CheckPermissionRequestScope,
};
use lenso_capability_notification_transactional as notification;
use lenso_capability_organization_directory as directory;
use lenso_capability_organization_invitation as public;
use lenso_capability_organization_invitation_worker as worker;
use lenso_capability_organization_membership as membership;
use lenso_capability_organization_membership::{
    CheckMembershipRequest, OrganizationMembershipInvocationError,
};
use lenso_capability_organization_membership_admin as membership_admin;
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{PluginDependencies, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

pub use operator::{OrganizationInvitationOperator, OrganizationInvitationOperatorError};

const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CALLERS: usize = 64;
const MAX_ID_BYTES: usize = 512;
const MAX_IDEMPOTENCY_BYTES: usize = 200;
const MAX_REASON_BYTES: usize = 2_000;
const DEFAULT_TOKEN_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const DEFAULT_COMMAND_LEASE_SECONDS: i64 = 120;
const DEFAULT_MAX_COMMAND_ATTEMPTS: i32 = 8;
const DEFAULT_RETRY_BASE_SECONDS: i64 = 30;

const INVITATION_READ: &str = "organization.invitations.read";
const INVITATION_MANAGE: &str = "organization.invitations.manage";
const INVITATION_EXPIRE: &str = "organization.invitations.expire";
const INVITATION_DISPATCH: &str = "organization.invitations.dispatch";

/// Immutable configuration for one Organization Invitation Plugin Instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationInvitationConfig {
    schema: String,
    database_url_secret: String,
    token_pepper_secret: String,
    token_derivation_secret: String,
    auth_issuer: String,
    auth_assertion_public_key: String,
    management_callers: Vec<String>,
    acceptance_callers: Vec<String>,
    worker_callers: Vec<String>,
    invitation_url_base: String,
    #[serde(default = "default_locale")]
    locale: String,
    #[serde(default = "default_token_ttl_seconds")]
    token_ttl_seconds: i64,
    #[serde(default = "default_command_lease_seconds")]
    command_lease_seconds: i64,
    #[serde(default = "default_max_command_attempts")]
    max_command_attempts: i32,
    #[serde(default = "default_retry_base_seconds")]
    retry_base_seconds: i64,
}

impl OrganizationInvitationConfig {
    /// Creates and validates immutable Organization Invitation configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        token_pepper_secret: impl Into<String>,
        token_derivation_secret: impl Into<String>,
        auth_issuer: impl Into<String>,
        auth_assertion_public_key: impl Into<String>,
        management_callers: Vec<String>,
        acceptance_callers: Vec<String>,
        worker_callers: Vec<String>,
        invitation_url_base: impl Into<String>,
    ) -> Result<Self, OrganizationInvitationConfigError> {
        let config = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            token_pepper_secret: token_pepper_secret.into(),
            token_derivation_secret: token_derivation_secret.into(),
            auth_issuer: auth_issuer.into(),
            auth_assertion_public_key: auth_assertion_public_key.into(),
            management_callers,
            acceptance_callers,
            worker_callers,
            invitation_url_base: invitation_url_base.into(),
            locale: default_locale(),
            token_ttl_seconds: DEFAULT_TOKEN_TTL_SECONDS,
            command_lease_seconds: DEFAULT_COMMAND_LEASE_SECONDS,
            max_command_attempts: DEFAULT_MAX_COMMAND_ATTEMPTS,
            retry_base_seconds: DEFAULT_RETRY_BASE_SECONDS,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), OrganizationInvitationConfigError> {
        schema::schema_plan(self.schema.clone())
            .map_err(|_| OrganizationInvitationConfigError::InvalidSchema)?;
        let secret_refs = [
            &self.database_url_secret,
            &self.token_pepper_secret,
            &self.token_derivation_secret,
        ];
        if secret_refs
            .iter()
            .any(|value| !valid_secret_reference(value))
            || secret_refs.iter().collect::<BTreeSet<_>>().len() != secret_refs.len()
        {
            return Err(OrganizationInvitationConfigError::InvalidSecretReference);
        }
        if !valid_identifier(&self.auth_issuer, 256) {
            return Err(OrganizationInvitationConfigError::InvalidAuthIssuer);
        }
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| OrganizationInvitationConfigError::InvalidAuthPublicKey)?;
        validate_callers(&self.management_callers)
            .map_err(|()| OrganizationInvitationConfigError::InvalidManagementCallers)?;
        validate_callers(&self.acceptance_callers)
            .map_err(|()| OrganizationInvitationConfigError::InvalidAcceptanceCallers)?;
        validate_callers(&self.worker_callers)
            .map_err(|()| OrganizationInvitationConfigError::InvalidWorkerCallers)?;
        let url = Url::parse(&self.invitation_url_base)
            .map_err(|_| OrganizationInvitationConfigError::InvalidInvitationUrl)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || self.invitation_url_base.len() > 2_048
        {
            return Err(OrganizationInvitationConfigError::InvalidInvitationUrl);
        }
        if !matches!(self.locale.as_str(), "en" | "en-US") {
            return Err(OrganizationInvitationConfigError::InvalidLocale);
        }
        if !(300..=2_592_000).contains(&self.token_ttl_seconds)
            || !(30..=3_600).contains(&self.command_lease_seconds)
            || !(1..=20).contains(&self.max_command_attempts)
            || !(1..=3_600).contains(&self.retry_base_seconds)
        {
            return Err(OrganizationInvitationConfigError::InvalidBounds);
        }
        Ok(())
    }

    fn verifier(&self) -> Result<ActorAssertionVerifier, RuntimeFailure> {
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| RuntimeFailure::InvalidResolvedPlan {
            detail: "Organization Invitation Auth verification key is invalid".to_owned(),
        })
    }
}

/// Invalid immutable Organization Invitation configuration.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OrganizationInvitationConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("database, pepper, and derivation secrets require distinct valid references")]
    InvalidSecretReference,
    #[error("invalid Auth issuer")]
    InvalidAuthIssuer,
    #[error("invalid Auth assertion public key")]
    InvalidAuthPublicKey,
    #[error("management_callers must contain unique exact Instance keys")]
    InvalidManagementCallers,
    #[error("acceptance_callers must contain unique exact Instance keys")]
    InvalidAcceptanceCallers,
    #[error("worker_callers must contain unique exact Instance keys")]
    InvalidWorkerCallers,
    #[error("invitation_url_base must be a query-free HTTPS URL")]
    InvalidInvitationUrl,
    #[error("locale must be `en` or `en-US`")]
    InvalidLocale,
    #[error("token, lease, retry, or attempt bounds are invalid")]
    InvalidBounds,
}

fn validate_config(config: &OrganizationInvitationConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Organization Invitation configuration is invalid: {error}"),
        })
}

#[derive(Clone)]
struct PreparedOrganizationInvitation {
    postgres: OwnedPostgres,
    token_pepper: Rc<Zeroizing<Vec<u8>>>,
    token_derivation: Rc<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for PreparedOrganizationInvitation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedOrganizationInvitation")
            .field("schema", &self.postgres.schema())
            .finish_non_exhaustive()
    }
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct PostgresOrganizationInvitationPlugin {
    #[config]
    config: OrganizationInvitationConfig,
    secrets: Port<secrets::SecretsClient>,
    membership: Port<membership::OrganizationMembershipClient>,
    access: Port<access::AccessControlClient>,
    directory: Port<directory::OrganizationDirectoryClient>,
    membership_admin: Port<membership_admin::OrganizationMembershipAdminClient>,
    notification: Port<notification::TransactionalClient>,
    prepared: Rc<RefCell<Option<PreparedOrganizationInvitation>>>,
}

impl fmt::Debug for PostgresOrganizationInvitationPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresOrganizationInvitationPlugin")
            .field("schema", &self.config.schema)
            .field("prepared", &self.prepared.borrow().is_some())
            .finish_non_exhaustive()
    }
}

#[lenso::provides(public::OrganizationInvitation, worker::OrganizationInvitationWorker)]
impl PostgresOrganizationInvitationPlugin {}

impl PostgresOrganizationInvitationPlugin {
    async fn invite(
        &self,
        context: Ctx,
        request: public::InviteRequest,
    ) -> PluginResult<public::InviteResponse, public::InviteError> {
        let (caller, actor) = self
            .authorize_management::<public::InviteError>(
                &context,
                &self.config.management_callers,
                public::CAPABILITY_ID,
                public::INVITE_OPERATION,
                &request.organization_id,
                INVITATION_MANAGE,
            )
            .await?;
        let email = normalize_email(&request.email)
            .ok_or_else(|| PluginError::domain(public::InviteError::InvalidRequest))?;
        if !valid_idempotency_key(&request.idempotency_key) {
            return Err(PluginError::domain(public::InviteError::InvalidRequest));
        }
        self.active_organization::<public::InviteError>(&context, &request.organization_id)
            .await?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let invitation_id = Uuid::new_v4();
        let token = token::derive_token(&prepared.token_derivation, invitation_id, 1)
            .map_err(token_runtime)?;
        let token_hash =
            token::hash_token(&token, &prepared.token_pepper).map_err(token_runtime)?;
        let hash = request_hash(&request)?;
        let result = storage::create_invitation(
            &prepared.postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            invitation_id,
            &request.organization_id,
            &actor,
            &email,
            &email,
            &token_hash,
            self.config.token_ttl_seconds,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(public::InviteError::from_storage(failure)))?;
        self.token_response(&result)
    }

    async fn get_invitation(
        &self,
        context: Ctx,
        request: public::GetInvitationRequest,
    ) -> PluginResult<public::GetInvitationResponse, public::GetInvitationError> {
        self.authorize_management::<public::GetInvitationError>(
            &context,
            &self.config.management_callers,
            public::CAPABILITY_ID,
            public::GET_INVITATION_OPERATION,
            &request.organization_id,
            INVITATION_READ,
        )
        .await?;
        if !valid_invitation_ref(&request.invitation_ref) {
            return Err(PluginError::domain(
                public::GetInvitationError::InvalidRequest,
            ));
        }
        let record = storage::get_invitation(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &request.organization_id,
            &request.invitation_ref,
        )
        .await
        .map_err(storage_runtime)?
        .ok_or_else(|| PluginError::domain(public::GetInvitationError::InvitationNotFound))?;
        wire_cast(&record.view)
    }

    async fn list_invitations(
        &self,
        context: Ctx,
        request: public::ListInvitationsRequest,
    ) -> PluginResult<public::ListInvitationsResponse, public::ListInvitationsError> {
        self.authorize_management::<public::ListInvitationsError>(
            &context,
            &self.config.management_callers,
            public::CAPABILITY_ID,
            public::LIST_INVITATIONS_OPERATION,
            &request.organization_id,
            INVITATION_READ,
        )
        .await?;
        if !(1..=100).contains(&request.limit) {
            return Err(PluginError::domain(
                public::ListInvitationsError::InvalidRequest,
            ));
        }
        let cursor = match request.cursor.as_deref() {
            Some(value) => Some(storage::decode_invitation_cursor(value).ok_or_else(|| {
                PluginError::domain(public::ListInvitationsError::InvalidRequest)
            })?),
            None => None,
        };
        let normalized_email = match request.email.as_deref() {
            Some(value) => Some(normalize_email(value).ok_or_else(|| {
                PluginError::domain(public::ListInvitationsError::InvalidRequest)
            })?),
            None => None,
        };
        let state = request.state.as_ref().map(public_list_state);
        let mut records = storage::list_invitations(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &storage::InvitationFilters {
                organization_id: &request.organization_id,
                state,
                email_normalized: normalized_email.as_deref(),
                cursor: cursor.as_ref(),
                limit: request.limit + 1,
            },
        )
        .await
        .map_err(storage_runtime)?;
        let next_cursor = if records.len() > usize::try_from(request.limit).unwrap_or(0) {
            records.truncate(usize::try_from(request.limit).unwrap_or(0));
            records
                .last()
                .map(storage::encode_invitation_cursor)
                .transpose()
                .map_err(storage_runtime)?
        } else {
            None
        };
        wire_cast(&serde_json::json!({"items": records, "next_cursor": next_cursor}))
    }

    async fn resend(
        &self,
        context: Ctx,
        request: public::ResendRequest,
    ) -> PluginResult<public::ResendResponse, public::ResendError> {
        let (caller, actor) = self
            .authorize_management::<public::ResendError>(
                &context,
                &self.config.management_callers,
                public::CAPABILITY_ID,
                public::RESEND_OPERATION,
                &request.organization_id,
                INVITATION_MANAGE,
            )
            .await?;
        let (invitation_id, expected_revision) = parse_mutation(
            &request.organization_id,
            &request.invitation_id,
            &request.expected_revision,
            &request.idempotency_key,
        )
        .ok_or_else(|| PluginError::domain(public::ResendError::InvalidRequest))?;
        self.active_organization::<public::ResendError>(&context, &request.organization_id)
            .await?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let current = storage::get_invitation_by_id(&prepared.postgres, invitation_id)
            .await
            .map_err(storage_runtime)?
            .ok_or_else(|| PluginError::domain(public::ResendError::InvitationNotFound))?;
        if current.view.organization_id != request.organization_id {
            return Err(PluginError::domain(public::ResendError::InvitationNotFound));
        }
        let generation = current.token_generation.checked_add(1).ok_or_else(|| {
            PluginError::runtime(RuntimeFailure::Internal {
                detail: "Organization Invitation token generation overflowed".to_owned(),
            })
        })?;
        let token = token::derive_token(&prepared.token_derivation, invitation_id, generation)
            .map_err(token_runtime)?;
        let token_hash =
            token::hash_token(&token, &prepared.token_pepper).map_err(token_runtime)?;
        let hash = request_hash(&request)?;
        let result = storage::resend_invitation(
            &prepared.postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            invitation_id,
            &actor,
            expected_revision,
            &token_hash,
            self.config.token_ttl_seconds,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(public::ResendError::from_storage(failure)))?;
        self.token_response(&result)
    }

    async fn revoke(
        &self,
        context: Ctx,
        request: public::RevokeRequest,
    ) -> PluginResult<public::RevokeResponse, public::RevokeError> {
        let (caller, actor) = self
            .authorize_management::<public::RevokeError>(
                &context,
                &self.config.management_callers,
                public::CAPABILITY_ID,
                public::REVOKE_OPERATION,
                &request.organization_id,
                INVITATION_MANAGE,
            )
            .await?;
        let (invitation_id, expected_revision) = parse_mutation(
            &request.organization_id,
            &request.invitation_id,
            &request.expected_revision,
            &request.idempotency_key,
        )
        .filter(|_| valid_text(&request.reason, MAX_REASON_BYTES))
        .ok_or_else(|| PluginError::domain(public::RevokeError::InvalidRequest))?;
        let hash = request_hash(&request)?;
        let invitation = storage::revoke_invitation(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            invitation_id,
            &actor,
            expected_revision,
            &request.reason,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(public::RevokeError::from_storage(failure)))?;
        wire_cast(&invitation)
    }

    fn token_response<R, E>(
        &self,
        result: &storage::TokenOperationResult,
    ) -> Result<R, PluginError<E>>
    where
        R: DeserializeOwned,
    {
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let token = if result.disclose_token {
            Some(
                token::derive_token(
                    &prepared.token_derivation,
                    result.invitation.invitation_id,
                    result.token_generation,
                )
                .map_err(token_runtime)?
                .to_string(),
            )
        } else {
            None
        };
        let mut value = serde_json::to_value(&result.invitation).map_err(serialization_runtime)?;
        let object = value.as_object_mut().ok_or_else(|| {
            PluginError::runtime(RuntimeFailure::Internal {
                detail: "Organization Invitation response is not an object".to_owned(),
            })
        })?;
        object.insert("token_returned".to_owned(), result.disclose_token.into());
        object.insert("invitation_token".to_owned(), token.into());
        serde_json::from_value(value).map_err(serialization_runtime)
    }
}

#[cfg(test)]
mod tests {
    use lenso_auth_sdk::ActorAssertionIssuer;

    use super::*;

    fn valid_config() -> OrganizationInvitationConfig {
        let issuer = ActorAssertionIssuer::new("auth.users", b"invitation test signing key");
        OrganizationInvitationConfig::new(
            "organization_invitation_v1",
            "organization-invitation/database-url",
            "organization-invitation/token-pepper",
            "organization-invitation/token-derivation",
            "auth.users",
            issuer.public_key_base64(),
            vec!["organization-admin-api".to_owned()],
            vec!["invitation-accept-api".to_owned()],
            vec!["organization-invitation-worker".to_owned()],
            "https://app.example.com/organization/invitations/accept",
        )
        .unwrap()
    }

    #[test]
    fn configuration_rejects_shared_secret_material_and_unbounded_urls() {
        let mut config = valid_config();
        config.token_pepper_secret = config.database_url_secret.clone();
        assert_eq!(
            config.validate(),
            Err(OrganizationInvitationConfigError::InvalidSecretReference)
        );

        let mut config = valid_config();
        config.invitation_url_base = "https://app.example.com/accept?token=forbidden".to_owned();
        assert_eq!(
            config.validate(),
            Err(OrganizationInvitationConfigError::InvalidInvitationUrl)
        );

        let mut config = valid_config();
        config.worker_callers.push(config.worker_callers[0].clone());
        assert_eq!(
            config.validate(),
            Err(OrganizationInvitationConfigError::InvalidWorkerCallers)
        );
    }

    #[test]
    fn email_normalization_is_conservative_and_org_identifiers_are_stable() {
        assert_eq!(
            normalize_email("  Member+Team@Example.COM  "),
            Some("member+team@example.com".to_owned())
        );
        assert_eq!(normalize_email("missing-domain@"), None);
        assert_eq!(normalize_email("dot..dot@example.com"), None);
        assert!(valid_invitation_ref("INV-42"));
        assert!(valid_invitation_ref(&Uuid::new_v4().to_string()));
        assert!(!valid_invitation_ref("INV-0001"));
    }

    #[test]
    fn invitation_urls_encode_secret_query_material() {
        let config = valid_config();
        let id = Uuid::new_v4();
        let id_string = id.to_string();
        let mut url = Url::parse(&config.invitation_url_base).unwrap();
        url.query_pairs_mut()
            .append_pair("invitation_id", &id_string)
            .append_pair("token", "token with reserved?characters")
            .append_pair("revision", "7");
        let parsed = Url::parse(url.as_str()).unwrap();
        let pairs = parsed
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            pairs.get("invitation_id").map(std::convert::AsRef::as_ref),
            Some(id_string.as_str())
        );
        assert_eq!(
            pairs.get("token").map(std::convert::AsRef::as_ref),
            Some("token with reserved?characters")
        );
        assert_eq!(
            pairs.get("revision").map(std::convert::AsRef::as_ref),
            Some("7")
        );
    }
}

trait ManagementRoleError: Sized {
    fn unauthenticated() -> Self;
    fn forbidden() -> Self;
    fn invalid_request() -> Self;
    fn organization_not_found() -> Self;
    fn organization_inactive() -> Self;
    fn from_storage(failure: storage::DomainFailure) -> Self;
}

macro_rules! impl_management_error {
    ($($error:path),+ $(,)?) => {
        $(impl ManagementRoleError for $error {
            fn unauthenticated() -> Self { Self::Unauthenticated }
            fn forbidden() -> Self { Self::Forbidden }
            fn invalid_request() -> Self { Self::InvalidRequest }
            fn organization_not_found() -> Self { Self::OrganizationNotFound }
            fn organization_inactive() -> Self { Self::OrganizationInactive }
            fn from_storage(failure: storage::DomainFailure) -> Self {
                match failure {
                    storage::DomainFailure::InvitationNotFound => Self::InvitationNotFound,
                    storage::DomainFailure::InvitationExists => Self::InvitationExists,
                    storage::DomainFailure::RevisionConflict => Self::RevisionConflict,
                    storage::DomainFailure::IdempotencyConflict => Self::IdempotencyConflict,
                    storage::DomainFailure::InvalidTransition
                    | storage::DomainFailure::TokenInvalid
                    | storage::DomainFailure::InvitationExpired
                    | storage::DomainFailure::AcceptanceInProgress => Self::InvalidTransition,
                }
            }
        })+
    };
}

impl_management_error!(
    public::InviteError,
    public::GetInvitationError,
    public::ListInvitationsError,
    public::ResendError,
    public::RevokeError,
);

trait AcceptStorageError {
    fn from_storage(failure: storage::DomainFailure) -> Self;
}

impl AcceptStorageError for public::AcceptError {
    fn from_storage(failure: storage::DomainFailure) -> Self {
        match failure {
            storage::DomainFailure::InvitationNotFound => Self::InvitationNotFound,
            storage::DomainFailure::RevisionConflict => Self::RevisionConflict,
            storage::DomainFailure::IdempotencyConflict => Self::IdempotencyConflict,
            storage::DomainFailure::InvalidTransition
            | storage::DomainFailure::InvitationExists => Self::InvalidTransition,
            storage::DomainFailure::TokenInvalid => Self::TokenInvalid,
            storage::DomainFailure::InvitationExpired => Self::InvitationExpired,
            storage::DomainFailure::AcceptanceInProgress => Self::AcceptanceInProgress,
        }
    }
}

trait WorkerRoleError: Sized {
    fn unauthenticated() -> Self;
    fn forbidden() -> Self;
    fn invalid_request() -> Self;
}

macro_rules! impl_worker_error {
    ($($error:path),+ $(,)?) => {
        $(impl WorkerRoleError for $error {
            fn unauthenticated() -> Self { Self::Unauthenticated }
            fn forbidden() -> Self { Self::Forbidden }
            fn invalid_request() -> Self { Self::InvalidRequest }
        })+
    };
}

impl_worker_error!(worker::ExpireDueError, worker::DispatchDueError);

fn request_hash<T: Serialize, E>(request: &T) -> Result<Vec<u8>, PluginError<E>> {
    serde_json::to_vec(request)
        .map(|wire| Sha256::digest(wire).to_vec())
        .map_err(serialization_runtime)
}

fn wire_cast<T: DeserializeOwned, E>(value: &impl Serialize) -> Result<T, PluginError<E>> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(serialization_runtime)
}

#[allow(clippy::needless_pass_by_value)]
fn serialization_runtime<E>(error: serde_json::Error) -> PluginError<E> {
    PluginError::runtime(RuntimeFailure::Internal {
        detail: format!("Organization Invitation wire serialization failed: {error}"),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn storage_runtime<E>(error: storage::StorageError) -> PluginError<E> {
    PluginError::runtime(storage_failure(error))
}

#[allow(clippy::needless_pass_by_value)]
fn storage_failure(error: storage::StorageError) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn token_runtime<E>(error: token::TokenError) -> PluginError<E> {
    PluginError::runtime(RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    })
}

fn format_time(value: OffsetDateTime) -> Result<String, storage::StorageError> {
    value
        .format(&Rfc3339)
        .map_err(|error| storage::StorageError::InvalidStoredData {
            detail: format!("invitation timestamp cannot be formatted: {error}"),
        })
}

fn normalize_email(value: &str) -> Option<String> {
    let value = value.trim();
    if !(3..=320).contains(&value.len()) || !value.is_ascii() {
        return None;
    }
    let (local, domain) = value.split_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 255
        || domain.contains('@')
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
        })
    {
        return None;
    }
    let labels = domain.split('.').collect::<Vec<_>>();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn parse_mutation(
    organization_id: &str,
    invitation_id: &str,
    expected_revision: &str,
    idempotency_key: &str,
) -> Option<(Uuid, i64)> {
    if !valid_opaque_id(organization_id, MAX_ID_BYTES) || !valid_idempotency_key(idempotency_key) {
        return None;
    }
    Some((
        Uuid::parse_str(invitation_id).ok()?,
        expected_revision.parse().ok().filter(|value| *value > 0)?,
    ))
}

fn valid_invitation_ref(value: &str) -> bool {
    Uuid::parse_str(value).is_ok()
        || value.strip_prefix("INV-").is_some_and(|number| {
            !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && !number.starts_with('0')
        })
}

fn valid_token_input(value: &str) -> bool {
    (32..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn valid_idempotency_key(value: &str) -> bool {
    valid_opaque_id(value, MAX_IDEMPOTENCY_BYTES)
}

fn valid_opaque_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    valid_opaque_id(value, maximum) && !value.contains('/')
}

fn valid_secret_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 256
        && !reference.starts_with('/')
        && !reference.ends_with('/')
        && !reference.contains("//")
        && reference
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && valid_opaque_id(reference, 256)
}

fn validate_callers(callers: &[String]) -> Result<(), ()> {
    if callers.is_empty()
        || callers.len() > MAX_CALLERS
        || callers.iter().any(|caller| !valid_identifier(caller, 256))
        || callers.iter().collect::<BTreeSet<_>>().len() != callers.len()
    {
        Err(())
    } else {
        Ok(())
    }
}

fn public_list_state(value: &public::ListInvitationsRequestState) -> &'static str {
    match value {
        public::ListInvitationsRequestState::Pending => "pending",
        public::ListInvitationsRequestState::Accepted => "accepted",
        public::ListInvitationsRequestState::Revoked => "revoked",
        public::ListInvitationsRequestState::Expired => "expired",
    }
}

fn default_locale() -> String {
    "en".to_owned()
}

const fn default_token_ttl_seconds() -> i64 {
    DEFAULT_TOKEN_TTL_SECONDS
}

const fn default_command_lease_seconds() -> i64 {
    DEFAULT_COMMAND_LEASE_SECONDS
}

const fn default_max_command_attempts() -> i32 {
    DEFAULT_MAX_COMMAND_ATTEMPTS
}

const fn default_retry_base_seconds() -> i64 {
    DEFAULT_RETRY_BASE_SECONDS
}

impl PostgresOrganizationInvitationPlugin {
    fn prepared(&self) -> Result<PreparedOrganizationInvitation, RuntimeFailure> {
        self.prepared
            .borrow()
            .clone()
            .ok_or_else(|| RuntimeFailure::PluginFailure {
                detail: "Organization Invitation Plugin is not prepared".to_owned(),
            })
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorize_management<E: ManagementRoleError>(
        &self,
        context: &Ctx,
        allowed_callers: &[String],
        capability: &str,
        operation: &str,
        organization_id: &str,
        permission: &str,
    ) -> Result<(String, String), PluginError<E>> {
        let caller = Self::allowed_caller(context, allowed_callers)
            .ok_or_else(|| PluginError::domain(E::forbidden()))?;
        let actor = self
            .authenticated_user_subject(context, capability, operation)
            .map_err(|()| PluginError::domain(E::unauthenticated()))?;
        if !valid_opaque_id(organization_id, MAX_ID_BYTES) {
            return Err(PluginError::domain(E::invalid_request()));
        }
        let active = self
            .require_membership(context, organization_id, &actor)
            .await
            .map_err(PluginError::runtime)?;
        let allowed = self
            .permission(context, organization_id, &actor, permission)
            .await
            .map_err(PluginError::runtime)?;
        if !active || !allowed {
            return Err(PluginError::domain(E::forbidden()));
        }
        Ok((caller, actor))
    }

    async fn authorize_worker<E: WorkerRoleError>(
        &self,
        context: &Ctx,
        operation: &str,
        organization_id: &str,
        permission: &str,
    ) -> Result<(String, String), PluginError<E>> {
        let caller = Self::allowed_caller(context, &self.config.worker_callers)
            .ok_or_else(|| PluginError::domain(E::forbidden()))?;
        let actor = self
            .authenticated_worker_subject(context, worker::CAPABILITY_ID, operation)
            .map_err(|()| PluginError::domain(E::unauthenticated()))?;
        if !valid_opaque_id(organization_id, MAX_ID_BYTES) {
            return Err(PluginError::domain(E::invalid_request()));
        }
        let active = self
            .require_membership(context, organization_id, &actor)
            .await
            .map_err(PluginError::runtime)?;
        let allowed = self
            .permission(context, organization_id, &actor, permission)
            .await
            .map_err(PluginError::runtime)?;
        if !active || !allowed {
            return Err(PluginError::domain(E::forbidden()));
        }
        Ok((caller, actor))
    }

    fn authorize_acceptance(
        &self,
        context: &Ctx,
        operation: &str,
    ) -> Result<(String, String), public::AcceptError> {
        let caller = Self::allowed_caller(context, &self.config.acceptance_callers)
            .ok_or(public::AcceptError::Forbidden)?;
        let actor = self
            .authenticated_user_subject(context, public::CAPABILITY_ID, operation)
            .map_err(|()| public::AcceptError::Unauthenticated)?;
        Ok((caller, actor))
    }

    fn allowed_caller(context: &Ctx, allowed: &[String]) -> Option<String> {
        context.caller_instance().and_then(|caller| {
            allowed
                .iter()
                .any(|entry| entry == caller)
                .then(|| caller.to_owned())
        })
    }

    fn authenticated_user_subject(
        &self,
        context: &Ctx,
        capability: &str,
        operation: &str,
    ) -> Result<String, ()> {
        let actor = self
            .config
            .verifier()
            .map_err(|_| ())?
            .project_context::<UserInvitationActor>(context, capability, operation, &UtcClock)
            .map_err(|_| ())?;
        valid_opaque_id(&actor.subject, MAX_ID_BYTES)
            .then_some(actor.subject)
            .ok_or(())
    }

    fn authenticated_worker_subject(
        &self,
        context: &Ctx,
        capability: &str,
        operation: &str,
    ) -> Result<String, ()> {
        let actor = self
            .config
            .verifier()
            .map_err(|_| ())?
            .project_context::<WorkerInvitationActor>(context, capability, operation, &UtcClock)
            .map_err(|_| ())?;
        valid_opaque_id(&actor.subject, MAX_ID_BYTES)
            .then_some(actor.subject)
            .ok_or(())
    }

    async fn require_membership(
        &self,
        context: &Ctx,
        organization_id: &str,
        subject: &str,
    ) -> Result<bool, RuntimeFailure> {
        self.membership
            .check_membership_with_context(
                context.clone(),
                CheckMembershipRequest {
                    organization_id: organization_id.to_owned(),
                    subject: subject.to_owned(),
                },
            )
            .await
            .map(|response| response.active)
            .map_err(|error| match error {
                OrganizationMembershipInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                    detail: "Organization Membership rejected an invitation authorization query"
                        .to_owned(),
                },
                OrganizationMembershipInvocationError::Runtime(error) => error,
            })
    }

    async fn permission(
        &self,
        context: &Ctx,
        organization_id: &str,
        subject: &str,
        permission: &str,
    ) -> Result<bool, RuntimeFailure> {
        self.access
            .check_permission_with_context(
                context.clone(),
                CheckPermissionRequest {
                    subject: subject.to_owned(),
                    scope: CheckPermissionRequestScope {
                        kind: "organization".to_owned(),
                        id: organization_id.to_owned(),
                    },
                    permission: permission.to_owned(),
                },
            )
            .await
            .map(|response| response.allowed)
            .map_err(|error| match error {
                AccessControlInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                    detail: "Access Control rejected an invitation authorization query".to_owned(),
                },
                AccessControlInvocationError::Runtime(error) => error,
            })
    }

    async fn active_organization<E: ManagementRoleError>(
        &self,
        context: &Ctx,
        organization_id: &str,
    ) -> Result<(), PluginError<E>> {
        match self
            .directory
            .get_organization_with_context(
                context.clone(),
                directory::GetOrganizationRequest {
                    organization_id: organization_id.to_owned(),
                },
            )
            .await
        {
            Ok(response) if response.active => Ok(()),
            Ok(_) => Err(PluginError::domain(E::organization_inactive())),
            Err(directory::OrganizationDirectoryInvocationError::Domain(
                directory::GetOrganizationError::OrganizationNotFound,
            )) => Err(PluginError::domain(E::organization_not_found())),
            Err(directory::OrganizationDirectoryInvocationError::Domain(_)) => {
                Err(PluginError::domain(E::forbidden()))
            }
            Err(directory::OrganizationDirectoryInvocationError::Runtime(error)) => {
                Err(PluginError::runtime(error))
            }
        }
    }
}

impl Lifecycle for PostgresOrganizationInvitationPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let database_url = resolve_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.database_url_secret,
        )
        .await?;
        let pepper = resolve_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.token_pepper_secret,
        )
        .await?;
        let derivation = resolve_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.token_derivation_secret,
        )
        .await?;
        if pepper.len() < 32 || derivation.len() < 32 || pepper.as_bytes() == derivation.as_bytes()
        {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Organization Invitation token secrets must be distinct and contain at least 256 bits"
                    .to_owned(),
            });
        }
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema::schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })?;
        let token_pepper = Rc::new(Zeroizing::new(pepper.as_bytes().to_vec()));
        let token_derivation = Rc::new(Zeroizing::new(derivation.as_bytes().to_vec()));
        self.prepared
            .borrow_mut()
            .replace(PreparedOrganizationInvitation {
                postgres,
                token_pepper,
                token_derivation,
            });
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct UserInvitationActor {
    subject: String,
}

impl TypedActor for UserInvitationActor {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        if assertion.actor_kind() != "user" {
            return Err(ActorProjectionError::UnexpectedActorKind {
                expected: "user".to_owned(),
                actual: assertion.actor_kind().to_owned(),
            });
        }
        Ok(Self {
            subject: assertion.subject().to_owned(),
        })
    }
}

#[derive(Clone, Debug)]
struct WorkerInvitationActor {
    subject: String,
}

impl TypedActor for WorkerInvitationActor {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        if !matches!(assertion.actor_kind(), "user" | "service_account") {
            return Err(ActorProjectionError::UnexpectedActorKind {
                expected: "user or service_account".to_owned(),
                actual: assertion.actor_kind().to_owned(),
            });
        }
        Ok(Self {
            subject: assertion.subject().to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct UtcClock;

impl AssertionClock for UtcClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

async fn resolve_secret(
    secrets: &SecretsClient,
    dependencies: &PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|response| Zeroizing::new(response.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: format!("Organization Invitation secret `{reference}` was rejected"),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

impl PostgresOrganizationInvitationPlugin {
    async fn accept(
        &self,
        context: Ctx,
        request: public::AcceptRequest,
    ) -> PluginResult<public::AcceptResponse, public::AcceptError> {
        let (caller, actor) = self
            .authorize_acceptance(&context, public::ACCEPT_OPERATION)
            .map_err(PluginError::domain)?;
        let invitation_id = Uuid::parse_str(&request.invitation_id)
            .ok()
            .filter(|_| valid_idempotency_key(&request.idempotency_key))
            .filter(|_| valid_token_input(&request.token))
            .ok_or_else(|| PluginError::domain(public::AcceptError::InvalidRequest))?;
        let expected_revision = request
            .expected_revision
            .parse::<i64>()
            .ok()
            .filter(|revision| *revision > 0)
            .ok_or_else(|| PluginError::domain(public::AcceptError::InvalidRequest))?;
        let hash = request_hash(&request)?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        if let Some(replay) = storage::lookup_accept_replay(
            &prepared.postgres,
            &caller,
            &request.idempotency_key,
            &actor,
            &hash,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(public::AcceptError::from_storage(failure)))?
        {
            return match replay {
                storage::AcceptStart::Replay(response) => wire_cast(&response),
                storage::AcceptStart::InProgress | storage::AcceptStart::Execute(_) => Err(
                    PluginError::domain(public::AcceptError::AcceptanceInProgress),
                ),
            };
        }
        let invitation = storage::get_invitation_by_id(&prepared.postgres, invitation_id)
            .await
            .map_err(storage_runtime)?
            .ok_or_else(|| PluginError::domain(public::AcceptError::InvitationNotFound))?;
        if invitation.view.state != "pending" {
            return Err(PluginError::domain(public::AcceptError::InvalidTransition));
        }
        let stored_hash = invitation
            .token_hash
            .as_deref()
            .ok_or_else(|| PluginError::domain(public::AcceptError::TokenInvalid))?;
        if !token::verify_token(&request.token, &prepared.token_pepper, stored_hash)
            .map_err(token_runtime)?
        {
            return Err(PluginError::domain(public::AcceptError::TokenInvalid));
        }
        let start = storage::begin_accept(
            &prepared.postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            invitation_id,
            &actor,
            expected_revision,
            invitation.token_generation,
            stored_hash,
            self.config.command_lease_seconds,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(public::AcceptError::from_storage(failure)))?;
        match start {
            storage::AcceptStart::Replay(response) => wire_cast(&response),
            storage::AcceptStart::InProgress => Err(PluginError::domain(
                public::AcceptError::AcceptanceInProgress,
            )),
            storage::AcceptStart::Execute(command) => {
                let response = self
                    .execute_acceptance_command(&context, &prepared.postgres, &command)
                    .await
                    .map_err(PluginError::runtime)?;
                wire_cast(&response)
            }
        }
    }

    async fn expire_due(
        &self,
        context: Ctx,
        request: worker::ExpireDueRequest,
    ) -> PluginResult<worker::ExpireDueResponse, worker::ExpireDueError> {
        let (caller, actor) = self
            .authorize_worker::<worker::ExpireDueError>(
                &context,
                worker::EXPIRE_DUE_OPERATION,
                &request.organization_id,
                INVITATION_EXPIRE,
            )
            .await?;
        if !(1..=100).contains(&request.limit) || !valid_idempotency_key(&request.idempotency_key) {
            return Err(PluginError::domain(worker::ExpireDueError::InvalidRequest));
        }
        let hash = request_hash(&request)?;
        let result = storage::expire_due(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            &actor,
            request.limit,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|_| PluginError::domain(worker::ExpireDueError::IdempotencyConflict))?;
        wire_cast(&result)
    }

    async fn dispatch_due(
        &self,
        context: Ctx,
        request: worker::DispatchDueRequest,
    ) -> PluginResult<worker::DispatchDueResponse, worker::DispatchDueError> {
        let (caller, actor) = self
            .authorize_worker::<worker::DispatchDueError>(
                &context,
                worker::DISPATCH_DUE_OPERATION,
                &request.organization_id,
                INVITATION_DISPATCH,
            )
            .await?;
        if !(1..=100).contains(&request.limit) || !valid_idempotency_key(&request.idempotency_key) {
            return Err(PluginError::domain(
                worker::DispatchDueError::InvalidRequest,
            ));
        }
        let hash = request_hash(&request)?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        if let Some(replay) = storage::begin_dispatch_batch(
            &prepared.postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            &actor,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|_| PluginError::domain(worker::DispatchDueError::IdempotencyConflict))?
        {
            return wire_cast(&replay);
        }
        let commands = storage::claim_due_commands(
            &prepared.postgres,
            &request.organization_id,
            request.limit,
            self.config.command_lease_seconds,
        )
        .await
        .map_err(storage_runtime)?;
        let mut result = storage::DispatchResult {
            processed: i64::try_from(commands.len()).map_err(|_| {
                PluginError::runtime(RuntimeFailure::Internal {
                    detail: "Organization Invitation dispatch count overflowed".to_owned(),
                })
            })?,
            completed: 0,
            retry_scheduled: 0,
            permanent_failed: 0,
            has_more: false,
        };
        for command in &commands {
            match self
                .execute_command(&context, &prepared, command)
                .await
                .map_err(storage_runtime)?
            {
                CommandDisposition::Completed => result.completed += 1,
                CommandDisposition::RetryScheduled => result.retry_scheduled += 1,
                CommandDisposition::PermanentFailure => result.permanent_failed += 1,
            }
        }
        result.has_more = storage::has_due_commands(&prepared.postgres, &request.organization_id)
            .await
            .map_err(storage_runtime)?;
        storage::complete_dispatch_batch(
            &prepared.postgres,
            &caller,
            &request.idempotency_key,
            &result,
        )
        .await
        .map_err(storage_runtime)?;
        wire_cast(&result)
    }

    async fn execute_acceptance_command(
        &self,
        context: &Ctx,
        postgres: &OwnedPostgres,
        command: &storage::CommandRecord,
    ) -> Result<storage::AcceptedRecord, RuntimeFailure> {
        let subject =
            command
                .acceptance_subject
                .clone()
                .ok_or_else(|| RuntimeFailure::Internal {
                    detail: "Organization Invitation membership command has no subject".to_owned(),
                })?;
        let result = self
            .membership_admin
            .add_member_with_context(
                context.clone(),
                membership_admin::AddMemberRequest {
                    idempotency_key: command.command_key.clone(),
                    organization_id: command.organization_id.clone(),
                    subject,
                },
            )
            .await;
        match result {
            Ok(response) => storage::complete_accept(
                postgres,
                command,
                &response.membership_id,
                &response.revision,
            )
            .await
            .map_err(storage_failure),
            Err(membership_admin::OrganizationMembershipAdminAddMemberInvocationError::Domain(
                membership_admin::AddMemberError::IdempotencyConflict,
            )) => {
                storage::fail_command(postgres, command, "membership_idempotency_conflict")
                    .await
                    .map_err(storage_failure)?;
                Err(RuntimeFailure::PluginFailure {
                    detail: "Organization Membership Admin reported an idempotency conflict"
                        .to_owned(),
                })
            }
            Err(membership_admin::OrganizationMembershipAdminAddMemberInvocationError::Domain(
                _,
            )) => {
                storage::fail_command(postgres, command, "membership_rejected")
                    .await
                    .map_err(storage_failure)?;
                Err(RuntimeFailure::PluginFailure {
                    detail: "Organization Membership Admin rejected invitation acceptance"
                        .to_owned(),
                })
            }
            Err(
                membership_admin::OrganizationMembershipAdminAddMemberInvocationError::Runtime(
                    error,
                ),
            ) => {
                self.schedule_command_retry(postgres, command, "membership_unavailable")
                    .await
                    .map_err(storage_failure)?;
                Err(error)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandDisposition {
    Completed,
    RetryScheduled,
    PermanentFailure,
}

impl PostgresOrganizationInvitationPlugin {
    async fn execute_command(
        &self,
        context: &Ctx,
        prepared: &PreparedOrganizationInvitation,
        command: &storage::CommandRecord,
    ) -> Result<CommandDisposition, storage::StorageError> {
        let Some(invitation) =
            storage::command_matches_invitation(&prepared.postgres, command).await?
        else {
            storage::supersede_command(&prepared.postgres, command).await?;
            return Ok(CommandDisposition::Completed);
        };
        match command.kind.as_str() {
            "add_member" => {
                let Some(subject) = command.acceptance_subject.clone() else {
                    storage::fail_command(
                        &prepared.postgres,
                        command,
                        "missing_acceptance_subject",
                    )
                    .await?;
                    return Ok(CommandDisposition::PermanentFailure);
                };
                match self
                    .membership_admin
                    .add_member_with_context(
                        context.clone(),
                        membership_admin::AddMemberRequest {
                            idempotency_key: command.command_key.clone(),
                            organization_id: command.organization_id.clone(),
                            subject,
                        },
                    )
                    .await
                {
                    Ok(response) => {
                        storage::complete_accept(
                            &prepared.postgres,
                            command,
                            &response.membership_id,
                            &response.revision,
                        )
                        .await?;
                        Ok(CommandDisposition::Completed)
                    }
                    Err(
                        membership_admin::OrganizationMembershipAdminAddMemberInvocationError::Domain(
                            membership_admin::AddMemberError::IdempotencyConflict,
                        ),
                    ) => {
                        storage::fail_command(
                            &prepared.postgres,
                            command,
                            "membership_idempotency_conflict",
                        )
                        .await?;
                        Ok(CommandDisposition::PermanentFailure)
                    }
                    Err(
                        membership_admin::OrganizationMembershipAdminAddMemberInvocationError::Domain(
                            _,
                        ),
                    ) => {
                        storage::fail_command(
                            &prepared.postgres,
                            command,
                            "membership_rejected",
                        )
                        .await?;
                        Ok(CommandDisposition::PermanentFailure)
                    }
                    Err(
                        membership_admin::OrganizationMembershipAdminAddMemberInvocationError::Runtime(
                            _,
                        ),
                    ) => {
                        self.schedule_command_retry(
                            &prepared.postgres,
                            command,
                            "membership_unavailable",
                        )
                        .await?;
                        Ok(CommandDisposition::RetryScheduled)
                    }
                }
            }
            "notify_invitation" => {
                let organization = match self
                    .directory
                    .get_organization_with_context(
                        context.clone(),
                        directory::GetOrganizationRequest {
                            organization_id: command.organization_id.clone(),
                        },
                    )
                    .await
                {
                    Ok(response) if response.active => response,
                    Ok(_) => {
                        storage::fail_command(&prepared.postgres, command, "organization_inactive")
                            .await?;
                        return Ok(CommandDisposition::PermanentFailure);
                    }
                    Err(directory::OrganizationDirectoryInvocationError::Domain(
                        directory::GetOrganizationError::Unknown(_),
                    )) => {
                        return self
                            .retry_or_fail_command(
                                &prepared.postgres,
                                command,
                                "organization_directory_unknown",
                            )
                            .await;
                    }
                    Err(directory::OrganizationDirectoryInvocationError::Domain(_)) => {
                        storage::fail_command(
                            &prepared.postgres,
                            command,
                            "organization_directory_rejected",
                        )
                        .await?;
                        return Ok(CommandDisposition::PermanentFailure);
                    }
                    Err(directory::OrganizationDirectoryInvocationError::Runtime(_)) => {
                        self.schedule_command_retry(
                            &prepared.postgres,
                            command,
                            "organization_directory_unavailable",
                        )
                        .await?;
                        return Ok(CommandDisposition::RetryScheduled);
                    }
                };
                let Some(generation) = command.token_generation else {
                    storage::fail_command(&prepared.postgres, command, "missing_token_generation")
                        .await?;
                    return Ok(CommandDisposition::PermanentFailure);
                };
                let Ok(token) = token::derive_token(
                    &prepared.token_derivation,
                    command.invitation_id,
                    generation,
                ) else {
                    storage::fail_command(&prepared.postgres, command, "token_derivation_failed")
                        .await?;
                    return Ok(CommandDisposition::PermanentFailure);
                };
                let Some(stored_hash) = invitation.token_hash.as_deref() else {
                    storage::supersede_command(&prepared.postgres, command).await?;
                    return Ok(CommandDisposition::Completed);
                };
                if !token::verify_token(&token, &prepared.token_pepper, stored_hash)
                    .unwrap_or(false)
                {
                    storage::fail_command(&prepared.postgres, command, "token_derivation_mismatch")
                        .await?;
                    return Ok(CommandDisposition::PermanentFailure);
                }
                let Ok(invitation_url) =
                    self.invitation_url(command.invitation_id, &token, invitation.view.revision)
                else {
                    storage::fail_command(&prepared.postgres, command, "invalid_invitation_url")
                        .await?;
                    return Ok(CommandDisposition::PermanentFailure);
                };
                let locale = if self.config.locale == "en-US" {
                    notification::CreateOrganizationInvitationRequestRecipientLocale::EnUS
                } else {
                    notification::CreateOrganizationInvitationRequestRecipientLocale::En
                };
                let request = notification::CreateOrganizationInvitationRequest {
                    source: notification::CreateOrganizationInvitationRequestSource {
                        entity_type: "organization_invitation".to_owned(),
                        entity_id: command.invitation_id.to_string(),
                    },
                    recipient: notification::CreateOrganizationInvitationRequestRecipient {
                        address: invitation.view.email.clone(),
                        display_name: None,
                        locale,
                    },
                    template: notification::CreateOrganizationInvitationRequestTemplate {
                        organization_id: invitation.view.organization_id.clone(),
                        organization_name: organization.name,
                        invitation_id: command.invitation_id.to_string(),
                        invitation_url,
                        inviter_display_name: None,
                        role_name: None,
                        expires_at: format_time(invitation.view.token_expires_at)?,
                    },
                    idempotency_key: command.command_key.clone(),
                    correlation_id: command.invitation_id.to_string(),
                    causation_id: Some(command.command_id.to_string()),
                    requested_by: Some(invitation.view.inviter_subject.clone()),
                };
                match self
                    .notification
                    .create_organization_invitation_with_context(context.clone(), request)
                    .await
                {
                    Ok(response) => {
                        storage::complete_notification_command(
                            &prepared.postgres,
                            command,
                            &response.intent_id,
                            &response.delivery_id,
                        )
                        .await?;
                        Ok(CommandDisposition::Completed)
                    }
                    Err(
                        notification::TransactionalCreateOrganizationInvitationInvocationError::Domain(
                            notification::CreateOrganizationInvitationError::IdempotencyConflict,
                        ),
                    ) => {
                        storage::fail_command(
                            &prepared.postgres,
                            command,
                            "notification_idempotency_conflict",
                        )
                        .await?;
                        Ok(CommandDisposition::PermanentFailure)
                    }
                    Err(
                        notification::TransactionalCreateOrganizationInvitationInvocationError::Domain(
                            notification::CreateOrganizationInvitationError::Unknown(_),
                        ),
                    ) => {
                        self.retry_or_fail_command(
                            &prepared.postgres,
                            command,
                            "notification_unknown",
                        )
                        .await
                    }
                    Err(
                        notification::TransactionalCreateOrganizationInvitationInvocationError::Domain(
                            _,
                        ),
                    ) => {
                        storage::fail_command(
                            &prepared.postgres,
                            command,
                            "notification_rejected",
                        )
                        .await?;
                        Ok(CommandDisposition::PermanentFailure)
                    }
                    Err(
                        notification::TransactionalCreateOrganizationInvitationInvocationError::Runtime(
                            _,
                        ),
                    ) => {
                        self.schedule_command_retry(
                            &prepared.postgres,
                            command,
                            "notification_unavailable",
                        )
                        .await?;
                        Ok(CommandDisposition::RetryScheduled)
                    }
                }
            }
            "notify_lifecycle" => {
                let Some(lifecycle) = command.lifecycle.as_deref() else {
                    storage::fail_command(&prepared.postgres, command, "missing_lifecycle").await?;
                    return Ok(CommandDisposition::PermanentFailure);
                };
                let (lifecycle, observed_at) = match lifecycle {
                    "accepted" => (
                        notification::ObserveInvitationLifecycleRequestLifecycle::Accepted,
                        invitation.view.accepted_at,
                    ),
                    "revoked" => (
                        notification::ObserveInvitationLifecycleRequestLifecycle::Revoked,
                        invitation.view.revoked_at,
                    ),
                    "expired" => (
                        notification::ObserveInvitationLifecycleRequestLifecycle::Expired,
                        invitation.view.expired_at,
                    ),
                    _ => {
                        storage::fail_command(&prepared.postgres, command, "invalid_lifecycle")
                            .await?;
                        return Ok(CommandDisposition::PermanentFailure);
                    }
                };
                let Some(observed_at) = observed_at else {
                    storage::fail_command(
                        &prepared.postgres,
                        command,
                        "missing_lifecycle_timestamp",
                    )
                    .await?;
                    return Ok(CommandDisposition::PermanentFailure);
                };
                let request = notification::ObserveInvitationLifecycleRequest {
                    observation_id: command.command_key.clone(),
                    organization_id: command.organization_id.clone(),
                    invitation_id: command.invitation_id.to_string(),
                    lifecycle,
                    observed_at: format_time(observed_at)?,
                };
                match self
                    .notification
                    .observe_invitation_lifecycle_with_context(context.clone(), request)
                    .await
                {
                    Ok(response) => {
                        storage::complete_lifecycle_command(
                            &prepared.postgres,
                            command,
                            response.recorded,
                        )
                        .await?;
                        Ok(CommandDisposition::Completed)
                    }
                    Err(
                        notification::TransactionalObserveInvitationLifecycleInvocationError::Domain(
                            notification::ObserveInvitationLifecycleError::ObservationConflict,
                        ),
                    ) => {
                        storage::fail_command(
                            &prepared.postgres,
                            command,
                            "notification_observation_conflict",
                        )
                        .await?;
                        Ok(CommandDisposition::PermanentFailure)
                    }
                    Err(
                        notification::TransactionalObserveInvitationLifecycleInvocationError::Domain(
                            notification::ObserveInvitationLifecycleError::Unknown(_),
                        ),
                    ) => {
                        self.retry_or_fail_command(
                            &prepared.postgres,
                            command,
                            "notification_unknown",
                        )
                        .await
                    }
                    Err(
                        notification::TransactionalObserveInvitationLifecycleInvocationError::Domain(
                            _,
                        ),
                    ) => {
                        storage::fail_command(
                            &prepared.postgres,
                            command,
                            "notification_rejected",
                        )
                        .await?;
                        Ok(CommandDisposition::PermanentFailure)
                    }
                    Err(
                        notification::TransactionalObserveInvitationLifecycleInvocationError::Runtime(
                            _,
                        ),
                    ) => {
                        self.schedule_command_retry(
                            &prepared.postgres,
                            command,
                            "notification_unavailable",
                        )
                        .await?;
                        Ok(CommandDisposition::RetryScheduled)
                    }
                }
            }
            _ => {
                storage::fail_command(&prepared.postgres, command, "unknown_command_kind").await?;
                Ok(CommandDisposition::PermanentFailure)
            }
        }
    }

    async fn retry_or_fail_command(
        &self,
        postgres: &OwnedPostgres,
        command: &storage::CommandRecord,
        error_code: &str,
    ) -> Result<CommandDisposition, storage::StorageError> {
        if command.attempts >= self.config.max_command_attempts {
            storage::fail_command(postgres, command, error_code).await?;
            Ok(CommandDisposition::PermanentFailure)
        } else {
            self.schedule_command_retry(postgres, command, error_code)
                .await?;
            Ok(CommandDisposition::RetryScheduled)
        }
    }

    async fn schedule_command_retry(
        &self,
        postgres: &OwnedPostgres,
        command: &storage::CommandRecord,
        error_code: &str,
    ) -> Result<(), storage::StorageError> {
        let exponent = u32::try_from(command.attempts.saturating_sub(1))
            .unwrap_or(0)
            .min(12);
        let multiplier = 1_i64.checked_shl(exponent).unwrap_or(i64::MAX);
        let delay = self
            .config
            .retry_base_seconds
            .saturating_mul(multiplier)
            .min(86_400);
        storage::retry_command(postgres, command, error_code, delay).await
    }

    fn invitation_url(
        &self,
        invitation_id: Uuid,
        token: &str,
        revision: i64,
    ) -> Result<String, RuntimeFailure> {
        let mut url = Url::parse(&self.config.invitation_url_base).map_err(|_| {
            RuntimeFailure::InvalidResolvedPlan {
                detail: "Organization Invitation URL base is invalid".to_owned(),
            }
        })?;
        url.query_pairs_mut()
            .append_pair("invitation_id", &invitation_id.to_string())
            .append_pair("token", token)
            .append_pair("revision", &revision.to_string());
        Ok(url.to_string())
    }
}
