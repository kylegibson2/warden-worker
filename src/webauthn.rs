//! Minimal WebAuthn (FIDO2) relying-party helpers for Bitwarden-compatible 2FA.
//!
//! Scoped to ES256 (P-256) credentials with `none`/opaque attestation extraction.
//! Signature verification uses Workers SubtleCrypto (see `crypto::verify_es256_signature`).

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use ciborium::value::Value as CborValue;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::crypto;
use crate::error::AppError;

const CHALLENGE_LEN: usize = 32;
const FLAG_UP: u8 = 0b0000_0001;
const FLAG_UV: u8 = 0b0000_0100;
const FLAG_AT: u8 = 0b0100_0000;
const FLAG_BE: u8 = 0b0000_1000;
const FLAG_BS: u8 = 0b0001_0000;

const COSE_KTY_EC2: i128 = 2;
const COSE_ALG_ES256: i128 = -7;
const COSE_CRV_P256: i128 = 1;

/// Relying party identity derived from `BASE_URL`.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    pub rp_id: String,
    pub origin: String,
    pub name: String,
}

impl RelyingParty {
    pub fn from_base_url(base_url: &str) -> Result<Self, AppError> {
        let base = base_url.trim_end_matches('/');
        let parsed = url::Url::parse(base).map_err(|_| {
            AppError::BadRequest(
                "BASE_URL is not a valid URL (required for WebAuthn 2FA)".to_string(),
            )
        })?;
        let rp_id = parsed.domain().ok_or_else(|| {
            AppError::BadRequest(
                "BASE_URL host must be a DNS domain for WebAuthn (IP addresses are not supported)"
                    .to_string(),
            )
        })?;
        let origin = parsed.origin().ascii_serialization();
        Ok(Self {
            rp_id: rp_id.to_string(),
            origin,
            name: rp_id.to_string(),
        })
    }
}

/// Credential stored in `twofactor.data` for provider type 7.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredCredential {
    /// Base64url (no pad) credential id.
    pub cred_id: String,
    /// Uncompressed P-256 public key bytes (0x04 || X || Y), base64url.
    pub public_key: String,
    pub sign_count: u32,
    #[serde(default)]
    pub backup_eligible: bool,
    #[serde(default)]
    pub backup_state: bool,
}

/// One registered WebAuthn key (Bitwarden/Vaultwarden-compatible list entry shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnRegistration {
    pub id: i32,
    pub name: String,
    #[serde(default)]
    pub migrated: bool,
    pub credential: StoredCredential,
}

impl WebauthnRegistration {
    pub fn to_client_json(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "migrated": self.migrated,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterChallengeState {
    pub challenge: String,
    pub user_handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginChallengeState {
    pub challenge: String,
    pub allow_credential_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPublicKeyCredential {
    #[allow(dead_code)]
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAttestationResponse {
    #[serde(alias = "AttestationObject")]
    pub attestation_object: String,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    pub client_data_json: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialAssertion {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticatorAssertionResponse,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAssertionResponse {
    pub authenticator_data: String,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
    #[allow(dead_code)]
    pub user_handle: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
}

fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, AppError> {
    URL_SAFE_NO_PAD
        .decode(s.trim())
        .or_else(|_| URL_SAFE.decode(s.trim()))
        .map_err(|_| AppError::BadRequest("Invalid base64url encoding".to_string()))
}

fn random_challenge() -> Result<Vec<u8>, AppError> {
    let mut bytes = vec![0u8; CHALLENGE_LEN];
    getrandom::fill(&mut bytes).map_err(|_| AppError::Internal)?;
    Ok(bytes)
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    let digest = Sha256::digest(rp_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn challenges_equal(expected_b64: &str, client_challenge_b64: &str) -> bool {
    let Ok(expected) = b64url_decode(expected_b64) else {
        return false;
    };
    let Ok(got) = b64url_decode(client_challenge_b64) else {
        return false;
    };
    expected.len() == got.len() && constant_time_eq::constant_time_eq(&expected, &got)
}

fn parse_client_data(client_data_b64: &str) -> Result<(ClientData, Vec<u8>), AppError> {
    let raw = b64url_decode(client_data_b64)?;
    let data: ClientData = serde_json::from_slice(&raw)
        .map_err(|_| AppError::BadRequest("Invalid clientDataJSON".to_string()))?;
    Ok((data, raw))
}

fn verify_client_data(
    data: &ClientData,
    expected_type: &str,
    expected_challenge_b64: &str,
    expected_origin: &str,
) -> Result<(), AppError> {
    if data.type_ != expected_type {
        return Err(AppError::BadRequest("Invalid clientData type".to_string()));
    }
    if !challenges_equal(expected_challenge_b64, &data.challenge) {
        return Err(AppError::BadRequest("Challenge mismatch".to_string()));
    }
    if data.origin != expected_origin {
        return Err(AppError::BadRequest(format!(
            "Origin mismatch (got {}, expected {})",
            data.origin, expected_origin
        )));
    }
    Ok(())
}

fn cbor_map_get<'a>(map: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, v)| match k {
        CborValue::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn cbor_map_get_int<'a>(map: &'a [(CborValue, CborValue)], key: i128) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, v)| match k {
        CborValue::Integer(i) if i128::from(*i) == key => Some(v),
        _ => None,
    })
}

fn cbor_as_bytes(v: &CborValue) -> Result<&[u8], AppError> {
    match v {
        CborValue::Bytes(b) => Ok(b),
        _ => Err(AppError::BadRequest("Expected CBOR bytes".to_string())),
    }
}

fn cbor_as_int(v: &CborValue) -> Result<i128, AppError> {
    match v {
        CborValue::Integer(i) => Ok(i128::from(*i)),
        _ => Err(AppError::BadRequest("Expected CBOR integer".to_string())),
    }
}

fn parse_cose_ec2_public_key(cose: &[u8]) -> Result<Vec<u8>, AppError> {
    let value: CborValue = ciborium::from_reader(cose)
        .map_err(|_| AppError::BadRequest("Invalid COSE public key".to_string()))?;
    let CborValue::Map(map) = value else {
        return Err(AppError::BadRequest("COSE key must be a map".to_string()));
    };
    let kty = cbor_map_get_int(&map, 1)
        .ok_or_else(|| AppError::BadRequest("Missing COSE kty".to_string()))
        .and_then(cbor_as_int)?;
    if kty != COSE_KTY_EC2 {
        return Err(AppError::BadRequest(
            "Only EC2 (P-256) WebAuthn credentials are supported".to_string(),
        ));
    }
    if let Some(alg) = cbor_map_get_int(&map, 3) {
        let alg = cbor_as_int(alg)?;
        if alg != COSE_ALG_ES256 {
            return Err(AppError::BadRequest(
                "Only ES256 WebAuthn credentials are supported".to_string(),
            ));
        }
    }
    let crv = cbor_map_get_int(&map, -1)
        .ok_or_else(|| AppError::BadRequest("Missing COSE crv".to_string()))
        .and_then(cbor_as_int)?;
    if crv != COSE_CRV_P256 {
        return Err(AppError::BadRequest(
            "Only P-256 WebAuthn credentials are supported".to_string(),
        ));
    }
    let x = cbor_map_get_int(&map, -2)
        .ok_or_else(|| AppError::BadRequest("Missing COSE x".to_string()))
        .and_then(cbor_as_bytes)?;
    let y = cbor_map_get_int(&map, -3)
        .ok_or_else(|| AppError::BadRequest("Missing COSE y".to_string()))
        .and_then(cbor_as_bytes)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(AppError::BadRequest(
            "Invalid P-256 public key size".to_string(),
        ));
    }
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(x);
    uncompressed.extend_from_slice(y);
    Ok(uncompressed)
}

struct AuthDataParsed {
    flags: u8,
    sign_count: u32,
    cred_id: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

fn parse_authenticator_data(
    auth_data: &[u8],
    rp: &RelyingParty,
) -> Result<AuthDataParsed, AppError> {
    if auth_data.len() < 37 {
        return Err(AppError::BadRequest(
            "authenticatorData too short".to_string(),
        ));
    }
    let expected_rp = rp_id_hash(&rp.rp_id);
    if auth_data[..32] != expected_rp {
        return Err(AppError::BadRequest("RP ID hash mismatch".to_string()));
    }
    let flags = auth_data[32];
    let sign_count = u32::from_be_bytes(auth_data[33..37].try_into().unwrap());

    let mut cred_id = None;
    let mut public_key = None;
    if flags & FLAG_AT != 0 {
        if auth_data.len() < 37 + 16 + 2 {
            return Err(AppError::BadRequest(
                "attestedCredentialData truncated".to_string(),
            ));
        }
        let mut offset = 37 + 16; // skip AAGUID
        let cred_len =
            u16::from_be_bytes(auth_data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if auth_data.len() < offset + cred_len {
            return Err(AppError::BadRequest("credential id truncated".to_string()));
        }
        let id = auth_data[offset..offset + cred_len].to_vec();
        offset += cred_len;
        let cose = &auth_data[offset..];
        let pk = parse_cose_ec2_public_key(cose)?;
        cred_id = Some(id);
        public_key = Some(pk);
    }

    Ok(AuthDataParsed {
        flags,
        sign_count,
        cred_id,
        public_key,
    })
}

fn validating_uncompressed_p256(pk: &[u8]) -> Result<(), AppError> {
    if pk.len() != 65 || pk[0] != 0x04 {
        return Err(AppError::BadRequest(
            "Invalid P-256 public key encoding".to_string(),
        ));
    }
    Ok(())
}

/// Finish registration: verify attestation response and return a stored credential.
pub fn finish_registration(
    rp: &RelyingParty,
    state: &RegisterChallengeState,
    credential: &RegisterPublicKeyCredential,
) -> Result<StoredCredential, AppError> {
    if credential.type_ != "public-key" {
        return Err(AppError::BadRequest("Invalid credential type".to_string()));
    }

    let (client_data, _client_raw) = parse_client_data(&credential.response.client_data_json)?;
    verify_client_data(
        &client_data,
        "webauthn.create",
        &state.challenge,
        &rp.origin,
    )?;

    let att_obj_bytes = b64url_decode(&credential.response.attestation_object)?;
    let att_obj: CborValue = ciborium::from_reader(att_obj_bytes.as_slice())
        .map_err(|_| AppError::BadRequest("Invalid attestationObject".to_string()))?;
    let CborValue::Map(map) = att_obj else {
        return Err(AppError::BadRequest(
            "attestationObject must be a CBOR map".to_string(),
        ));
    };
    let auth_data = cbor_map_get(&map, "authData")
        .ok_or_else(|| AppError::BadRequest("Missing authData".to_string()))
        .and_then(cbor_as_bytes)?;

    let parsed = parse_authenticator_data(auth_data, rp)?;
    if parsed.flags & FLAG_UP == 0 {
        return Err(AppError::BadRequest(
            "User presence required for WebAuthn registration".to_string(),
        ));
    }
    let cred_id = parsed
        .cred_id
        .ok_or_else(|| AppError::BadRequest("Missing attested credential".to_string()))?;
    let public_key = parsed
        .public_key
        .ok_or_else(|| AppError::BadRequest("Missing credential public key".to_string()))?;

    // Ensure rawId matches attested credential id.
    let raw_id = b64url_decode(&credential.raw_id)?;
    if raw_id != cred_id {
        return Err(AppError::BadRequest("Credential id mismatch".to_string()));
    }
    validating_uncompressed_p256(&public_key)?;

    Ok(StoredCredential {
        cred_id: b64url_encode(&cred_id),
        public_key: b64url_encode(&public_key),
        sign_count: parsed.sign_count,
        backup_eligible: parsed.flags & FLAG_BE != 0,
        backup_state: parsed.flags & FLAG_BS != 0,
    })
}

/// Build PublicKeyCredentialCreationOptions (+ Bitwarden status fields).
pub fn start_registration(
    rp: &RelyingParty,
    user_uuid: &str,
    user_email: &str,
    display_name: &str,
    exclude_cred_ids: &[String],
) -> Result<(Value, RegisterChallengeState), AppError> {
    let challenge = random_challenge()?;
    let challenge_b64 = b64url_encode(&challenge);

    let user_handle = if let Ok(uuid) = uuid::Uuid::parse_str(user_uuid) {
        b64url_encode(uuid.as_bytes())
    } else {
        b64url_encode(user_uuid.as_bytes())
    };

    let exclude: Vec<Value> = exclude_cred_ids
        .iter()
        .map(|id| {
            json!({
                "type": "public-key",
                "id": id,
            })
        })
        .collect();

    let options = json!({
        "challenge": challenge_b64,
        "rp": {
            "name": rp.name,
            "id": rp.rp_id,
        },
        "user": {
            "id": user_handle,
            "name": user_email,
            "displayName": display_name,
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 }
        ],
        "timeout": 60_000,
        "attestation": "none",
        "excludeCredentials": exclude,
        "authenticatorSelection": {
            "userVerification": "discouraged",
            "requireResidentKey": false,
            "residentKey": "discouraged",
        },
        "status": "ok",
        "errorMessage": "",
    });

    let state = RegisterChallengeState {
        challenge: challenge_b64,
        user_handle,
    };
    Ok((options, state))
}

/// Build PublicKeyCredentialRequestOptions for login 2FA.
pub fn start_authentication(
    rp: &RelyingParty,
    registrations: &[WebauthnRegistration],
) -> Result<(Value, LoginChallengeState), AppError> {
    if registrations.is_empty() {
        return Err(AppError::BadRequest(
            "No Webauthn devices registered".to_string(),
        ));
    }
    let challenge = random_challenge()?;
    let challenge_b64 = b64url_encode(&challenge);
    let allow_credential_ids: Vec<String> = registrations
        .iter()
        .map(|r| r.credential.cred_id.clone())
        .collect();

    let allow_credentials: Vec<Value> = allow_credential_ids
        .iter()
        .map(|id| {
            json!({
                "type": "public-key",
                "id": id,
            })
        })
        .collect();

    let app_id = format!("{}/app-id.json", rp.origin.trim_end_matches('/'));
    let options = json!({
        "challenge": challenge_b64,
        "timeout": 60_000,
        "rpId": rp.rp_id,
        "allowCredentials": allow_credentials,
        "userVerification": "discouraged",
        "extensions": {
            "appid": app_id,
        },
    });

    Ok((
        options,
        LoginChallengeState {
            challenge: challenge_b64,
            allow_credential_ids,
        },
    ))
}

/// Finish authentication; returns index of matching registration (for counter update).
pub async fn finish_authentication(
    rp: &RelyingParty,
    state: &LoginChallengeState,
    registrations: &mut [WebauthnRegistration],
    assertion_json: &str,
) -> Result<usize, AppError> {
    let assertion: PublicKeyCredentialAssertion = serde_json::from_str(assertion_json)
        .map_err(|_| AppError::BadRequest("Invalid WebAuthn assertion".to_string()))?;
    if assertion.type_ != "public-key" {
        return Err(AppError::BadRequest("Invalid credential type".to_string()));
    }

    let cred_id = b64url_encode(&b64url_decode(&assertion.raw_id)?);
    let idx = registrations
        .iter()
        .position(|r| {
            r.credential.cred_id == cred_id
                || r.credential.cred_id == assertion.id
                || assertion.id == r.credential.cred_id
        })
        .ok_or_else(|| AppError::BadRequest("Credential not present".to_string()))?;

    let allowed = state.allow_credential_ids.iter().any(|id| {
        id == &cred_id || id == &assertion.id || id == &registrations[idx].credential.cred_id
    });
    if !allowed {
        return Err(AppError::BadRequest(
            "Unknown WebAuthn credential".to_string(),
        ));
    }

    let (client_data, client_raw) = parse_client_data(&assertion.response.client_data_json)?;
    verify_client_data(&client_data, "webauthn.get", &state.challenge, &rp.origin)?;

    let auth_data = b64url_decode(&assertion.response.authenticator_data)?;
    let parsed = parse_authenticator_data(&auth_data, rp)?;
    if parsed.flags & FLAG_UP == 0 {
        return Err(AppError::BadRequest(
            "User presence required for WebAuthn login".to_string(),
        ));
    }
    let _ = FLAG_UV; // discouraged for 2FA — do not require

    let public_key = b64url_decode(&registrations[idx].credential.public_key)?;
    let signature = b64url_decode(&assertion.response.signature)?;
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&Sha256::digest(&client_raw));
    crypto::verify_es256_signature(&public_key, &signed, &signature).await?;

    // Counter check (WebAuthn §6.1.1): reject if both non-zero and new <= old.
    let stored_count = registrations[idx].credential.sign_count;
    if stored_count > 0 && parsed.sign_count > 0 && parsed.sign_count <= stored_count {
        return Err(AppError::BadRequest(
            "WebAuthn signature counter mismatch".to_string(),
        ));
    }

    let reg = &mut registrations[idx];
    reg.credential.sign_count = parsed.sign_count;
    if parsed.flags & FLAG_BE != 0 {
        reg.credential.backup_eligible = true;
    }
    reg.credential.backup_state = parsed.flags & FLAG_BS != 0;

    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_from_base_url() {
        let rp = RelyingParty::from_base_url("https://wardenworker.kylegibson.net/").unwrap();
        assert_eq!(rp.rp_id, "wardenworker.kylegibson.net");
        assert_eq!(rp.origin, "https://wardenworker.kylegibson.net");
    }

    #[test]
    fn rp_rejects_ip() {
        assert!(RelyingParty::from_base_url("https://127.0.0.1").is_err());
    }
}
