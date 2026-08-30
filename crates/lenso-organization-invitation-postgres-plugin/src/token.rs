use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const TOKEN_CONTEXT: &[u8] = b"lenso.organization-invitation.token.v1\0";
const ARGON_MEMORY_KIB: u32 = 19_456;
const ARGON_ITERATIONS: u32 = 2;
const ARGON_PARALLELISM: u32 = 1;

pub(crate) fn derive_token(
    derivation_secret: &[u8],
    invitation_id: Uuid,
    generation: i64,
) -> Result<Zeroizing<String>, TokenError> {
    if derivation_secret.len() < 32 || generation <= 0 {
        return Err(TokenError::InvalidSecret);
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(derivation_secret).map_err(|_| TokenError::InvalidSecret)?;
    mac.update(TOKEN_CONTEXT);
    mac.update(invitation_id.as_bytes());
    mac.update(&generation.to_be_bytes());
    Ok(Zeroizing::new(
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
    ))
}

pub(crate) fn hash_token(token: &str, pepper: &[u8]) -> Result<String, TokenError> {
    if pepper.len() < 32 {
        return Err(TokenError::InvalidSecret);
    }
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt).map_err(|_| TokenError::EntropyUnavailable)?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| TokenError::HashFailure)?;
    argon2()?
        .hash_password(&peppered(token, pepper), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| TokenError::HashFailure)
}

pub(crate) fn verify_token(
    token: &str,
    pepper: &[u8],
    encoded_hash: &str,
) -> Result<bool, TokenError> {
    if pepper.len() < 32 {
        return Err(TokenError::InvalidSecret);
    }
    let hash = PasswordHash::new(encoded_hash).map_err(|_| TokenError::InvalidStoredHash)?;
    Ok(argon2()?
        .verify_password(&peppered(token, pepper), &hash)
        .is_ok())
}

fn peppered(token: &str, pepper: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::with_capacity(token.len() + pepper.len() + 1));
    input.extend_from_slice(token.as_bytes());
    input.push(0);
    input.extend_from_slice(pepper);
    input
}

fn argon2() -> Result<Argon2<'static>, TokenError> {
    let params = Params::new(
        ARGON_MEMORY_KIB,
        ARGON_ITERATIONS,
        ARGON_PARALLELISM,
        Some(32),
    )
    .map_err(|_| TokenError::HashFailure)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum TokenError {
    #[error("token secret must contain at least 256 bits")]
    InvalidSecret,
    #[error("operating-system entropy is unavailable")]
    EntropyUnavailable,
    #[error("Argon2id token hashing failed")]
    HashFailure,
    #[error("stored Argon2id token hash is invalid")]
    InvalidStoredHash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_deterministic_by_generation_and_argon_hash_is_salted() {
        let derivation = [7_u8; 32];
        let pepper = [9_u8; 32];
        let id = Uuid::new_v4();
        let first = derive_token(&derivation, id, 1).unwrap();
        assert_eq!(first, derive_token(&derivation, id, 1).unwrap());
        assert_ne!(first, derive_token(&derivation, id, 2).unwrap());
        let hash_a = hash_token(&first, &pepper).unwrap();
        let hash_b = hash_token(&first, &pepper).unwrap();
        assert_ne!(hash_a, hash_b);
        assert!(verify_token(&first, &pepper, &hash_a).unwrap());
        assert!(!verify_token("wrong", &pepper, &hash_a).unwrap());
        assert!(hash_a.starts_with("$argon2id$v=19$"));
    }
}
