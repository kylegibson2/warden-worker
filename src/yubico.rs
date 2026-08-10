//! YubiCloud OTP validation (Yubico OTP Validation Protocol 2.0).
//!
//! Secrets / config:
//! - `YUBICO_CLIENT_ID` — client id from https://upgrade.yubico.com/getapikey/
//! - `YUBICO_SECRET_KEY` — base64 API key from the same page
//! - Optional `YUBICO_SERVER` — override verify host (default `https://api.yubico.com/wsapi/2.0/verify`)

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use worker::{Env, Fetch, Method, Request, RequestInit, Url};

use crate::crypto::hmac_sha1;
use crate::error::AppError;

const DEFAULT_VERIFY_URL: &str = "https://api.yubico.com/wsapi/2.0/verify";

fn env_string(env: &Env, name: &str) -> Result<String, AppError> {
    if let Ok(value) = env.secret(name) {
        return Ok(value.to_string());
    }
    if let Ok(value) = env.var(name) {
        return Ok(value.to_string());
    }
    Err(AppError::BadRequest(format!(
        "Missing `{name}`. Set it as a Worker secret (or variable)."
    )))
}

fn yubico_credentials(env: &Env) -> Result<(String, String), AppError> {
    Ok((
        env_string(env, "YUBICO_CLIENT_ID")?,
        env_string(env, "YUBICO_SECRET_KEY")?,
    ))
}

fn verify_url(env: &Env) -> String {
    env.var("YUBICO_SERVER")
        .ok()
        .map(|v| v.to_string())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_VERIFY_URL.to_string())
}

fn random_nonce() -> Result<String, AppError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| AppError::Internal)?;
    Ok(hex::encode(bytes))
}

async fn sign_params(secret_b64: &str, params: &[(&str, &str)]) -> Result<String, AppError> {
    let mut sorted: Vec<(&str, &str)> = params.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let line = sorted
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let key = B64
        .decode(secret_b64.trim())
        .map_err(|_| AppError::BadRequest("Invalid YUBICO_SECRET_KEY (expected base64)".into()))?;
    let mac = hmac_sha1(&key, line.as_bytes()).await?;
    Ok(B64.encode(mac))
}

fn parse_kv_body(body: &str) -> Vec<(String, String)> {
    body.lines()
        .filter_map(|line| {
            let line = line.trim().trim_end_matches('\r');
            if line.is_empty() {
                return None;
            }
            let (k, v) = line.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Ensure Yubico credentials are configured (for get-yubikey UI).
pub fn ensure_configured(env: &Env) -> Result<(), AppError> {
    yubico_credentials(env).map(|_| ())
}

/// Verify a YubiKey OTP against YubiCloud (or configured server).
pub async fn verify_otp(env: &Env, otp: &str) -> Result<(), AppError> {
    let otp = otp.trim();
    if otp.len() != 44 {
        return Err(AppError::BadRequest("Invalid Yubikey OTP length".into()));
    }

    let (client_id, secret) = yubico_credentials(env)?;
    let nonce = random_nonce()?;
    let base = verify_url(env);

    let params = [
        ("id", client_id.as_str()),
        ("nonce", nonce.as_str()),
        ("otp", otp),
    ];
    let signature = sign_params(&secret, &params).await?;

    let mut url = Url::parse(&base).map_err(|_| AppError::Internal)?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.clear();
        pairs.append_pair("id", &client_id);
        pairs.append_pair("otp", otp);
        pairs.append_pair("nonce", &nonce);
        pairs.append_pair("h", &signature);
    }

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let req = Request::new_with_init(url.as_str(), &init).map_err(AppError::Worker)?;
    let mut response = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    let status = response.status_code();
    let body = response.text().await.map_err(AppError::Worker)?;
    if status != 200 {
        log::error!("YubiCloud HTTP {status}: {body}");
        return Err(AppError::BadRequest(
            "Failed to verify Yubikey OTP against YubiCloud".into(),
        ));
    }

    let fields = parse_kv_body(&body);
    let get = |key: &str| {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    let resp_h = get("h").ok_or_else(|| AppError::BadRequest("Invalid YubiCloud response".into()))?;
    let resp_status = get("status")
        .ok_or_else(|| AppError::BadRequest("Invalid YubiCloud response".into()))?;
    let resp_otp = get("otp").unwrap_or("");
    let resp_nonce = get("nonce").unwrap_or("");

    // Verify response HMAC (all fields except h).
    let sign_fields: Vec<(&str, &str)> = fields
        .iter()
        .filter(|(k, _)| k != "h")
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let expected_h = sign_params(&secret, &sign_fields).await?;
    if !crate::crypto::ct_eq(&expected_h, resp_h) {
        return Err(AppError::BadRequest(
            "YubiCloud response signature mismatch".into(),
        ));
    }

    if resp_otp != otp || resp_nonce != nonce {
        return Err(AppError::BadRequest(
            "YubiCloud response did not match request".into(),
        ));
    }

    match resp_status {
        "OK" => Ok(()),
        "REPLAYED_OTP" => Err(AppError::BadRequest("Yubikey OTP already used".into())),
        "BAD_OTP" => Err(AppError::BadRequest("Invalid Yubikey OTP provided".into())),
        "NO_SUCH_CLIENT" => Err(AppError::BadRequest(
            "YUBICO_CLIENT_ID is not recognized by YubiCloud".into(),
        )),
        other => {
            log::warn!("YubiCloud status={other}");
            Err(AppError::BadRequest(format!(
                "Yubikey verification failed ({other})"
            )))
        }
    }
}
