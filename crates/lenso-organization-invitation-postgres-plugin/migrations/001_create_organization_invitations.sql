CREATE TABLE organization_invitation_sequences (
    organization_id TEXT PRIMARY KEY,
    next_number BIGINT NOT NULL CHECK (next_number > 0)
);

CREATE TABLE organization_invitations (
    invitation_id UUID PRIMARY KEY,
    organization_id TEXT NOT NULL,
    identifier TEXT NOT NULL,
    email TEXT NOT NULL,
    email_normalized TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'accepted', 'revoked', 'expired')),
    inviter_subject TEXT NOT NULL,
    acceptance_subject TEXT,
    membership_id TEXT,
    token_hash TEXT,
    token_generation BIGINT NOT NULL CHECK (token_generation > 0),
    token_expires_at TIMESTAMPTZ NOT NULL,
    token_consumed_at TIMESTAMPTZ,
    revision BIGINT NOT NULL CHECK (revision > 0),
    delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending', 'queued', 'failed', 'superseded')),
    delivery_intent_id TEXT,
    delivery_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    expired_at TIMESTAMPTZ,
    revoke_reason TEXT,
    UNIQUE (organization_id, identifier),
    CHECK ((state = 'pending' AND ((acceptance_subject IS NULL AND token_hash IS NOT NULL) OR (acceptance_subject IS NOT NULL AND token_hash IS NULL))) OR state <> 'pending'),
    CHECK ((state = 'accepted' AND acceptance_subject IS NOT NULL AND membership_id IS NOT NULL AND accepted_at IS NOT NULL) OR state <> 'accepted'),
    CHECK ((state = 'revoked' AND revoked_at IS NOT NULL) OR state <> 'revoked'),
    CHECK ((state = 'expired' AND expired_at IS NOT NULL) OR state <> 'expired')
);

CREATE UNIQUE INDEX organization_invitations_pending_email_idx
    ON organization_invitations (organization_id, email_normalized)
    WHERE state = 'pending';
CREATE INDEX organization_invitations_page_idx
    ON organization_invitations (organization_id, created_at DESC, invitation_id DESC);
CREATE INDEX organization_invitations_expire_idx
    ON organization_invitations (organization_id, token_expires_at ASC, invitation_id ASC)
    WHERE state = 'pending' AND acceptance_subject IS NULL;

CREATE TABLE organization_invitation_commands (
    command_id UUID PRIMARY KEY,
    organization_id TEXT NOT NULL,
    invitation_id UUID NOT NULL REFERENCES organization_invitations(invitation_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('notify_invitation', 'notify_lifecycle', 'add_member')),
    command_key TEXT NOT NULL UNIQUE,
    token_generation BIGINT,
    acceptance_subject TEXT,
    lifecycle TEXT CHECK (lifecycle IN ('accepted', 'revoked', 'expired')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'in_flight', 'completed', 'failed', 'superseded')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    last_error TEXT,
    provider_receipt JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    CHECK ((kind = 'notify_invitation' AND token_generation IS NOT NULL AND acceptance_subject IS NULL AND lifecycle IS NULL)
        OR (kind = 'notify_lifecycle' AND token_generation IS NULL AND acceptance_subject IS NULL AND lifecycle IS NOT NULL)
        OR (kind = 'add_member' AND token_generation IS NULL AND acceptance_subject IS NOT NULL AND lifecycle IS NULL))
);

CREATE INDEX organization_invitation_commands_due_idx
    ON organization_invitation_commands (organization_id, available_at ASC, command_id ASC)
    WHERE state IN ('pending', 'in_flight');

CREATE TABLE organization_invitation_mutations (
    caller_instance TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    operation TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    organization_id TEXT NOT NULL,
    invitation_id UUID REFERENCES organization_invitations(invitation_id) ON DELETE CASCADE,
    side_effect_command_id UUID REFERENCES organization_invitation_commands(command_id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('started', 'completed')),
    response JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (caller_instance, idempotency_key)
);

CREATE INDEX organization_invitation_mutations_resource_idx
    ON organization_invitation_mutations (organization_id, invitation_id);

CREATE TABLE organization_invitation_activity (
    activity_id UUID PRIMARY KEY,
    organization_id TEXT NOT NULL,
    invitation_id UUID NOT NULL REFERENCES organization_invitations(invitation_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    invitation_revision BIGINT NOT NULL CHECK (invitation_revision > 0),
    evidence JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX organization_invitation_activity_idx
    ON organization_invitation_activity (invitation_id, created_at ASC, activity_id ASC);
