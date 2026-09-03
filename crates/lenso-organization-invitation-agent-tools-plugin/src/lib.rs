//! Token-safe Console Agent Tools over Organization Invitation administration.

use lenso::prelude::*;
use lenso_capability_agent_tool_provider::{
    self as tools, CatalogRequest, CatalogResponse, ContentType, ExecuteError, ExecuteRequest,
    ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_capability_organization_invitation::{
    self as invitation, GetInvitationRequest, ListInvitationsRequest, RevokeRequest,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

const GET: &str = "organization_invitation_get";
const LIST: &str = "organization_invitation_list";
const REVOKE: &str = "organization_invitation_revoke";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct OrganizationInvitationAgentToolsPlugin {
    invitations: Port<invitation::OrganizationInvitationClient>,
}

#[lenso::provides(tools::ToolProvider)]
impl OrganizationInvitationAgentToolsPlugin {
    fn catalog(
        &self,
        _context: Ctx,
        _request: CatalogRequest,
    ) -> impl std::future::Future<Output = PluginResult<CatalogResponse, tools::CatalogError>> {
        let _ = self;
        futures::future::ready(Ok(CatalogResponse {
            tools: tool_definitions(),
        }))
    }

    async fn execute(
        &self,
        context: Ctx,
        request: ExecuteRequest,
    ) -> PluginResult<ExecuteResponse, ExecuteError> {
        match request.name.as_str() {
            GET => {
                let input = decode::<GetInvitationRequest>(&request)?;
                match self
                    .invitations
                    .get_invitation_with_context(context, input)
                    .await
                {
                    Ok(value) => success(GET, &value),
                    Err(
                        invitation::OrganizationInvitationGetInvitationInvocationError::Domain(
                            error,
                        ),
                    ) => Err(PluginError::domain(map_error(&error))),
                    Err(
                        invitation::OrganizationInvitationGetInvitationInvocationError::Runtime(
                            error,
                        ),
                    ) => Err(PluginError::runtime(error)),
                }
            }
            LIST => {
                let input = decode::<ListInvitationsRequest>(&request)?;
                match self
                    .invitations
                    .list_invitations_with_context(context, input)
                    .await
                {
                    Ok(value) => success(LIST, &value),
                    Err(
                        invitation::OrganizationInvitationListInvitationsInvocationError::Domain(
                            error,
                        ),
                    ) => Err(PluginError::domain(map_error(&error))),
                    Err(
                        invitation::OrganizationInvitationListInvitationsInvocationError::Runtime(
                            error,
                        ),
                    ) => Err(PluginError::runtime(error)),
                }
            }
            REVOKE => {
                let input = decode::<RevokeRequest>(&request)?;
                match self.invitations.revoke_with_context(context, input).await {
                    Ok(value) => success(REVOKE, &value),
                    Err(invitation::OrganizationInvitationRevokeInvocationError::Domain(error)) => {
                        Err(PluginError::domain(map_error(&error)))
                    }
                    Err(invitation::OrganizationInvitationRevokeInvocationError::Runtime(
                        error,
                    )) => Err(PluginError::runtime(error)),
                }
            }
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            GET,
            "Get one invitation without exposing a token.",
            include_str!(
                "../../lenso-capability-organization-invitation/schemas/get-invitation-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST,
            "List invitations with bounded cursor pagination and no tokens.",
            include_str!(
                "../../lenso-capability-organization-invitation/schemas/list-invitations-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            REVOKE,
            "Revoke an invitation using its current expected revision and caller-scoped idempotency key.",
            include_str!(
                "../../lenso-capability-organization-invitation/schemas/revoke-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
    ]
}

fn tool(
    name: &str,
    description: &str,
    schema: &str,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: serde_json::from_str::<serde_json::Value>(schema)
            .expect("Invitation Tool schema must be valid JSON")
            .to_string()
            .try_into()
            .expect("Invitation Tool schema must remain valid JSON"),
        execution,
    }
}
fn decode<T: DeserializeOwned>(request: &ExecuteRequest) -> PluginResult<T, ExecuteError> {
    serde_json::from_str(request.arguments_json.as_str())
        .map_err(|_| PluginError::domain(ExecuteError::InvalidArguments))
}
fn success<T: Serialize>(name: &str, value: &T) -> PluginResult<ExecuteResponse, ExecuteError> {
    let content = serde_json::to_string_pretty(value).map_err(|error| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!("Invitation Tool could not serialize its response: {error}"),
        })
    })?;
    Ok(ExecuteResponse {
        content_blocks: None,
        content,
        content_type: ContentType::Text,
        metadata_json: serde_json::json!({ "tool": name, "token_exposed": false })
            .to_string()
            .try_into()
            .expect("Invitation Tool metadata must be valid JSON"),
    })
}
trait DomainError {
    fn tool_error(&self) -> ExecuteError;
}
fn map_error(error: &impl DomainError) -> ExecuteError {
    error.tool_error()
}
fn rejected(code: &str) -> ExecuteError {
    ExecuteError::ExecutionFailed {
        payload: ExecutionFailedPayload {
            reason_code: code.to_owned(),
            message: "Organization Invitation rejected the operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": code })
                .to_string()
                .try_into()
                .expect("Invitation Tool error metadata must be valid JSON"),
        },
    }
}
macro_rules! impl_domain_error {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl DomainError for $ty {
                fn tool_error(&self) -> ExecuteError {
                    match self {
                        Self::InvalidRequest => ExecuteError::InvalidArguments,
                        Self::InvitationNotFound | Self::OrganizationNotFound => ExecuteError::NotFound,
                        Self::Forbidden | Self::Unauthenticated => ExecuteError::PermissionDenied,
                        Self::IdempotencyConflict => rejected("idempotency_conflict"),
                        Self::InvalidTransition => rejected("invalid_transition"),
                        Self::InvitationExists => rejected("invitation_exists"),
                        Self::OrganizationInactive => rejected("organization_inactive"),
                        Self::RevisionConflict => rejected("revision_conflict"),
                        Self::Unknown(_) => rejected("unknown_domain_error"),
                    }
                }
            }
        )+
    };
}
impl_domain_error!(
    invitation::GetInvitationError,
    invitation::ListInvitationsError,
    invitation::RevokeError
);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_excludes_every_token_producing_or_consuming_operation() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["plugin_id"],
            "lenso.organization-invitation.agent-tools"
        );
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(
            required[0]["capability_id"],
            "lenso.organization-invitation@1"
        );
        let tools = tool_definitions();
        assert_eq!(tools.len(), 3);
        assert!(
            tools
                .iter()
                .map(|tool| tool.name.as_str())
                .all(|name| !name.contains("invite")
                    && !name.contains("resend")
                    && !name.contains("accept")
                    && !name.contains("worker"))
        );
    }
}
