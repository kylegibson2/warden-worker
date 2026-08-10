use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use serde_json::Value;
use std::sync::Arc;
use worker::Env;

use crate::d1_query;
use crate::{
    auth::AuthUser,
    crypto::{
        base32_decode, ct_eq, generate_email_token, generate_recovery_code, generate_totp_secret,
        validate_totp,
    },
    db,
    error::AppError,
    handlers::allow_totp_drift,
    mail,
    models::twofactor::{
        ActivateEmailData, DeleteWebauthnData, DisableAuthenticatorData, DisableTwoFactorData,
        EmailTokenData, EnableAuthenticatorData, EnableWebauthnData, EnableYubikeyData,
        SendEmailData, SendEmailLoginData, TwoFactor, TwoFactorType, YubikeyMetadata,
    },
    models::user::{PasswordOrOtpData, User},
    webauthn::{self, LoginChallengeState, RegisterChallengeState, WebauthnRegistration},
    yubico, BaseUrl,
};

/// List all 2FA records for a user (excludes atype >= 1000).
pub(crate) async fn list_user_twofactors(
    db: &crate::db::Db,
    user_id: &str,
) -> Result<Vec<TwoFactor>, AppError> {
    db.prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000")
        .bind(&[user_id.to_string().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<TwoFactor>()
        .map_err(|_| AppError::Database)
}

/// Whether the user has 2FA enabled.
///
/// Authenticator (TOTP), Email, YubiKey, and WebAuthn count. Remember-device tokens do not.
pub(crate) fn is_twofactor_enabled(twofactors: &[TwoFactor]) -> bool {
    twofactors.iter().any(|tf| {
        tf.enabled
            && (tf.atype == TwoFactorType::Authenticator as i32
                || tf.atype == TwoFactorType::Email as i32
                || tf.atype == TwoFactorType::YubiKey as i32
                || (tf.atype == TwoFactorType::Webauthn as i32
                    && webauthn_registrations_from_data(&tf.data)
                        .map(|r| !r.is_empty())
                        .unwrap_or(false)))
    })
}

/// Enabled login providers for the Bitwarden two-factor challenge response.
pub(crate) fn enabled_twofactor_provider_ids(twofactors: &[TwoFactor]) -> Vec<i32> {
    let mut ids: Vec<i32> = twofactors
        .iter()
        .filter(|tf| {
            tf.enabled
                && (tf.atype == TwoFactorType::Authenticator as i32
                    || tf.atype == TwoFactorType::Email as i32
                    || tf.atype == TwoFactorType::YubiKey as i32
                    || (tf.atype == TwoFactorType::Webauthn as i32
                        && webauthn_registrations_from_data(&tf.data)
                            .map(|r| !r.is_empty())
                            .unwrap_or(false)))
        })
        .map(|tf| tf.atype)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn webauthn_registrations_from_data(
    data: &str,
) -> Result<Vec<crate::webauthn::WebauthnRegistration>, AppError> {
    serde_json::from_str(data)
        .map_err(|_| AppError::BadRequest("Could not decode WebAuthn 2FA data".to_string()))
}

/// Obscure an email for client UI (Vaultwarden-compatible).
pub(crate) fn obscure_email(email: &str) -> String {
    let Some((name, domain)) = email.rsplit_once('@') else {
        return "***".to_string();
    };
    let name_size = name.chars().count();
    let new_name = if (1..=3).contains(&name_size) {
        "*".repeat(name_size)
    } else {
        let stars = "*".repeat(name_size.saturating_sub(2));
        let prefix: String = name.chars().take(2).collect();
        format!("{prefix}{stars}")
    };
    format!("{new_name}@{domain}")
}

/// GET /api/two-factor - Get all enabled 2FA providers for current user
#[worker::send]
pub async fn get_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let twofactors = list_user_twofactors(&db, &user_id).await?;
    let twofactors: Vec<Value> = twofactors.iter().map(|tf| tf.to_json_provider()).collect();

    Ok(Json(serde_json::json!({
        "data": twofactors,
        "object": "list",
        "continuationToken": null,
    })))
}

/// POST /api/two-factor/get-authenticator - Get or generate TOTP secret
#[worker::send]
pub async fn get_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(&user, &data).await?;

    // Check if TOTP is already configured
    let existing: Option<Value> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[
            user_id.clone().into(),
            (TwoFactorType::Authenticator as i32).into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let (enabled, key) = match existing {
        Some(tf_value) => {
            let tf: TwoFactor = serde_json::from_value(tf_value).map_err(|_| AppError::Internal)?;
            (true, tf.data)
        }
        None => (false, generate_totp_secret()?),
    };

    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// POST /api/two-factor/authenticator - Activate TOTP
#[worker::send]
pub async fn activate_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    let key = data.key.to_uppercase();

    // Validate key format (Base32, 20 bytes = 32 characters without padding)
    let decoded_key = base32_decode(&key)?;
    if decoded_key.len() != 20 {
        return Err(AppError::BadRequest("Invalid key length".to_string()));
    }

    // Check if TOTP is already configured - reuse existing record for replay protection
    let existing: Option<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[
            user_id.clone().into(),
            (TwoFactorType::Authenticator as i32).into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()?;

    // Get last_used from existing record to prevent replay during reconfiguration
    let previous_last_used = existing.as_ref().map(|tf| tf.last_used).unwrap_or(0);

    // Validate TOTP code and capture time step for replay protection
    let allow_drift = allow_totp_drift(&env);
    let last_used_step = validate_totp(&data.token, &key, previous_last_used, allow_drift).await?;

    // Delete existing TOTP and any remember-device tokens bound to it to avoid stale bypass
    d1_query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype IN (?2, ?3)",
        &user_id,
        TwoFactorType::Authenticator as i32,
        TwoFactorType::Remember as i32
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Create new TOTP entry
    let mut twofactor = TwoFactor::new(user_id.clone(), TwoFactorType::Authenticator, key.clone());
    twofactor.last_used = last_used_step;

    d1_query!(
        &db,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &twofactor.uuid,
        &twofactor.user_uuid,
        twofactor.atype,
        twofactor.enabled as i32,
        &twofactor.data,
        twofactor.last_used
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Generate recovery code if not exists
    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// PUT /api/two-factor/authenticator - Same as POST
#[worker::send]
pub async fn activate_authenticator_put(
    state: State<Arc<Env>>,
    auth_user: AuthUser,
    json: Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    activate_authenticator(state, auth_user, json).await
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[worker::send]
pub async fn disable_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    let type_ = data.r#type;

    // Delete the specified 2FA type
    d1_query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &user_id,
        type_
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    log::info!("User {} disabled 2FA type {}", user_id, type_);

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": type_,
        "object": "twoFactorProvider"
    })))
}

/// DELETE /api/two-factor/authenticator - Disable TOTP with key verification
#[worker::send]
pub async fn disable_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    if data.r#type != TwoFactorType::Authenticator as i32 {
        return Err(AppError::BadRequest("Invalid two factor type".to_string()));
    }

    // Verify master password (OTP not supported in this minimal implementation)
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    // Fetch existing TOTP and verify key matches before deleting
    let existing: Option<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[user_id.clone().into(), data.r#type.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()?;

    let Some(tf) = existing else {
        return Err(AppError::BadRequest("TOTP not configured".to_string()));
    };

    // Compare keys case-insensitively (key is stored uppercased during activation)
    if !ct_eq(&tf.data, &data.key.to_uppercase()) {
        return Err(AppError::BadRequest(
            "TOTP key does not match recorded value".to_string(),
        ));
    }

    d1_query!(&db, "DELETE FROM twofactor WHERE uuid = ?1", &tf.uuid)
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    log::info!(
        "User {} disabled authenticator (2FA type {})",
        user_id,
        data.r#type
    );

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": data.r#type,
        "object": "twoFactorProvider"
    })))
}

/// PUT /api/two-factor/disable - Same as POST
#[worker::send]
pub async fn disable_twofactor_put(
    state: State<Arc<Env>>,
    auth_user: AuthUser,
    json: Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    disable_twofactor(state, auth_user, json).await
}

/// POST /api/two-factor/get-recover - Get recovery code
#[worker::send]
pub async fn get_recover(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(&user, &data).await?;

    Ok(Json(serde_json::json!({
        "code": user.totp_recover,
        "object": "twoFactorRecover"
    })))
}

// Helper functions

async fn validate_password_or_otp(user: &User, data: &PasswordOrOtpData) -> Result<(), AppError> {
    if let Some(ref password_hash) = data.master_password_hash {
        let verification = user.verify_master_password(password_hash).await?;
        if verification.is_valid() {
            return Ok(());
        }
    }

    // OTP validation would be handled here if we had protected actions support
    // For now, master password is required

    Err(AppError::Unauthorized("Invalid password".to_string()))
}

async fn generate_recovery_code_for_user(
    db: &crate::db::Db,
    user_id: &str,
) -> Result<(), AppError> {
    // Check if recovery code already exists
    let user_value: Value = db
        .prepare("SELECT totp_recover FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let totp_recover: Option<String> = user_value
        .get("totp_recover")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if totp_recover.is_none() {
        let recovery_code = generate_recovery_code()?;
        d1_query!(
            db,
            "UPDATE users SET totp_recover = ?1 WHERE id = ?2",
            &recovery_code,
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(())
}

/// POST /api/two-factor/get-email
#[worker::send]
pub async fn get_email(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    validate_password_or_otp(&user, &data).await?;

    let existing = find_twofactor(&db, &user_id, TwoFactorType::Email).await?;
    let (enabled, email) = match existing {
        Some(tf) => {
            let data = EmailTokenData::from_json(&tf.data)?;
            (true, Value::String(data.email))
        }
        None => (false, Value::Null),
    };

    Ok(Json(serde_json::json!({
        "email": email,
        "enabled": enabled,
        "object": "twoFactorEmail"
    })))
}

/// POST /api/two-factor/send-email — send ownership verification code while enabling Email 2FA.
#[worker::send]
pub async fn send_email(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<SendEmailData>,
) -> Result<StatusCode, AppError> {
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    let email = data.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(AppError::BadRequest("Invalid email".to_string()));
    }

    // Remove any prior email 2FA / pending challenge for a clean enable flow.
    d1_query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype IN (?2, ?3)",
        &user_id,
        TwoFactorType::Email as i32,
        TwoFactorType::EmailVerificationChallenge as i32
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let token = generate_email_token(EmailTokenData::TOKEN_DIGITS)?;
    let token_data = EmailTokenData::new(email.clone(), token.clone());
    let twofactor = TwoFactor::new(
        user_id,
        TwoFactorType::EmailVerificationChallenge,
        token_data.to_json()?,
    );

    d1_query!(
        &db,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &twofactor.uuid,
        &twofactor.user_uuid,
        twofactor.atype,
        twofactor.enabled as i32,
        &twofactor.data,
        twofactor.last_used
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    mail::send_two_factor_token(&env, &email, &token).await?;
    Ok(StatusCode::OK)
}

/// PUT /api/two-factor/email — confirm verification code and enable Email 2FA.
#[worker::send]
pub async fn activate_email(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<ActivateEmailData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    let mut twofactor = find_twofactor(&db, &user_id, TwoFactorType::EmailVerificationChallenge)
        .await?
        .ok_or_else(|| {
            AppError::BadRequest("Email verification challenge not found".to_string())
        })?;

    let mut email_data = EmailTokenData::from_json(&twofactor.data)?;
    let Some(issued) = email_data.last_token.clone() else {
        return Err(AppError::BadRequest("No token available".to_string()));
    };
    if !ct_eq(&issued, data.token.trim()) {
        return Err(AppError::BadRequest("Token is invalid".to_string()));
    }
    if email_data.email.trim().to_lowercase() != data.email.trim().to_lowercase() {
        return Err(AppError::BadRequest(
            "Email does not match challenge".to_string(),
        ));
    }

    email_data.reset_token();
    twofactor.atype = TwoFactorType::Email as i32;
    twofactor.data = email_data.to_json()?;

    d1_query!(
        &db,
        "UPDATE twofactor SET atype = ?1, data = ?2, last_used = 0 WHERE uuid = ?3",
        twofactor.atype,
        &twofactor.data,
        &twofactor.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "email": email_data.email,
        "enabled": true,
        "object": "twoFactorEmail"
    })))
}

/// POST /api/two-factor/send-email-login — unauthenticated; send login code after password check.
#[worker::send]
pub async fn send_email_login(
    State(env): State<Arc<Env>>,
    Json(data): Json<SendEmailLoginData>,
) -> Result<StatusCode, AppError> {
    let db = db::get_db(&env)?;

    let email = data
        .email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .ok_or_else(|| {
            AppError::Unauthorized("Username or password is incorrect. Try again.".to_string())
        })?;

    let user = User::find_by_email(&db, &email).await?.ok_or_else(|| {
        AppError::Unauthorized("Username or password is incorrect. Try again.".to_string())
    })?;

    let password_hash = data
        .master_password_hash
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Unauthorized("Username or password is incorrect. Try again.".to_string())
        })?;

    let verification = user.verify_master_password(password_hash).await?;
    if !verification.is_valid() {
        return Err(AppError::Unauthorized(
            "Username or password is incorrect. Try again.".to_string(),
        ));
    }

    send_login_email_token(&env, &db, &user.id).await?;
    Ok(StatusCode::OK)
}

/// Issue (or re-issue) a login email token for an already-enabled Email 2FA user.
pub(crate) async fn send_login_email_token(
    env: &Env,
    db: &crate::db::Db,
    user_id: &str,
) -> Result<(), AppError> {
    let mut twofactor = find_twofactor(db, user_id, TwoFactorType::Email)
        .await?
        .ok_or_else(|| AppError::BadRequest("Email 2FA is not enabled".to_string()))?;

    let mut email_data = EmailTokenData::from_json(&twofactor.data)?;
    let token = generate_email_token(EmailTokenData::TOKEN_DIGITS)?;
    email_data.set_token(token.clone());
    twofactor.data = email_data.to_json()?;

    d1_query!(
        db,
        "UPDATE twofactor SET data = ?1 WHERE uuid = ?2",
        &twofactor.data,
        &twofactor.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    mail::send_two_factor_token(env, &email_data.email, &token).await
}

/// Validate an Email 2FA code during `/identity/connect/token`.
pub(crate) async fn validate_email_login_code(
    db: &crate::db::Db,
    user_id: &str,
    token: &str,
    data: &str,
) -> Result<(), AppError> {
    let mut email_data = EmailTokenData::from_json(data)?;
    let mut twofactor = find_twofactor(db, user_id, TwoFactorType::Email)
        .await?
        .ok_or_else(|| AppError::BadRequest("Email 2FA is not enabled".to_string()))?;

    let Some(issued) = email_data.last_token.clone() else {
        return Err(AppError::BadRequest("No token available".to_string()));
    };

    if !ct_eq(&issued, token.trim()) {
        email_data.add_attempt();
        if email_data.attempts >= EmailTokenData::ATTEMPTS_LIMIT {
            email_data.reset_token();
        }
        twofactor.data = email_data.to_json()?;
        d1_query!(
            db,
            "UPDATE twofactor SET data = ?1 WHERE uuid = ?2",
            &twofactor.data,
            &twofactor.uuid
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        return Err(AppError::BadRequest("Token is invalid".to_string()));
    }

    let now = chrono::Utc::now().timestamp();
    if email_data.token_sent + EmailTokenData::EXPIRATION_SECS < now {
        email_data.reset_token();
        twofactor.data = email_data.to_json()?;
        d1_query!(
            db,
            "UPDATE twofactor SET data = ?1 WHERE uuid = ?2",
            &twofactor.data,
            &twofactor.uuid
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        return Err(AppError::BadRequest("Token has expired".to_string()));
    }

    email_data.reset_token();
    twofactor.data = email_data.to_json()?;
    d1_query!(
        db,
        "UPDATE twofactor SET data = ?1 WHERE uuid = ?2",
        &twofactor.data,
        &twofactor.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(())
}

async fn load_user(db: &crate::db::Db, user_id: &str) -> Result<User, AppError> {
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.to_string().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    serde_json::from_value(user_value).map_err(|_| AppError::Internal)
}

async fn find_twofactor(
    db: &crate::db::Db,
    user_id: &str,
    atype: TwoFactorType,
) -> Result<Option<TwoFactor>, AppError> {
    db.prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[user_id.to_string().into(), (atype as i32).into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()
}

/// Clear recovery code when no real 2FA providers remain.
async fn clear_recovery_if_no_twofactor(db: &crate::db::Db, user_id: &str) -> Result<(), AppError> {
    let remaining: Vec<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000 AND atype != ?2")
        .bind(&[
            user_id.to_string().into(),
            (TwoFactorType::Remember as i32).into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    if remaining.is_empty() {
        d1_query!(
            db,
            "UPDATE users SET totp_recover = NULL WHERE id = ?1",
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(())
}

fn jsonify_yubikeys(keys: &[String], enabled: bool, nfc: bool) -> Value {
    let mut result = serde_json::Map::new();
    for (i, key) in keys.iter().enumerate() {
        result.insert(format!("Key{}", i + 1), Value::String(key.clone()));
    }
    result.insert("enabled".into(), Value::Bool(enabled));
    result.insert("nfc".into(), Value::Bool(nfc));
    // Historical Bitwarden object name (also used by Vaultwarden).
    result.insert("object".into(), Value::String("twoFactorU2f".into()));
    Value::Object(result)
}

/// POST /api/two-factor/get-yubikey
#[worker::send]
pub async fn get_yubikey(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    yubico::ensure_configured(&env)?;
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    validate_password_or_otp(&user, &data).await?;

    let existing = find_twofactor(&db, &user_id, TwoFactorType::YubiKey).await?;
    match existing {
        Some(tf) => {
            let meta = YubikeyMetadata::from_json(&tf.data)?;
            Ok(Json(jsonify_yubikeys(&meta.keys, true, meta.nfc)))
        }
        None => Ok(Json(serde_json::json!({
            "enabled": false,
            "object": "twoFactorU2f",
        }))),
    }
}

/// POST/PUT /api/two-factor/yubikey — verify OTPs with YubiCloud and enable YubiKey 2FA.
#[worker::send]
pub async fn activate_yubikey(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableYubikeyData>,
) -> Result<Json<Value>, AppError> {
    yubico::ensure_configured(&env)?;
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash.clone(),
            otp: data.otp.clone(),
        },
    )
    .await?;

    let mut keys = Vec::new();
    for otp in data.otps() {
        let otp = otp.trim();
        // Empty or already-registered 12-char public ids are accepted without re-verify
        // (Vaultwarden-compatible reconfiguration).
        if otp.is_empty() {
            continue;
        }
        if otp.len() == 12 {
            keys.push(otp.to_lowercase());
            continue;
        }
        if otp.len() != 44 {
            return Err(AppError::BadRequest(
                "Invalid YubiKey OTP length".to_string(),
            ));
        }
        yubico::verify_otp(&env, otp).await?;
        keys.push(otp[..12].to_lowercase());
    }

    if keys.is_empty() {
        return Err(AppError::BadRequest(
            "At least one YubiKey OTP is required".to_string(),
        ));
    }

    keys.sort();
    keys.dedup();

    let meta = YubikeyMetadata {
        keys: keys.clone(),
        nfc: data.nfc,
    };

    d1_query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &user_id,
        TwoFactorType::YubiKey as i32
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let twofactor = TwoFactor::new(user_id.clone(), TwoFactorType::YubiKey, meta.to_json()?);
    d1_query!(
        &db,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &twofactor.uuid,
        &twofactor.user_uuid,
        twofactor.atype,
        twofactor.enabled as i32,
        &twofactor.data,
        twofactor.last_used
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(jsonify_yubikeys(&meta.keys, true, meta.nfc)))
}

/// PUT /api/two-factor/yubikey
#[worker::send]
pub async fn activate_yubikey_put(
    env: State<Arc<Env>>,
    auth_user: AuthUser,
    data: Json<EnableYubikeyData>,
) -> Result<Json<Value>, AppError> {
    activate_yubikey(env, auth_user, data).await
}

fn jsonify_webauthn(enabled: bool, registrations: &[WebauthnRegistration]) -> Value {
    let keys: Vec<Value> = registrations
        .iter()
        .map(WebauthnRegistration::to_client_json)
        .collect();
    serde_json::json!({
        "enabled": enabled,
        "keys": keys,
        "object": "twoFactorWebAuthn",
    })
}

fn jsonify_webauthn_u2f(enabled: bool, registrations: &[WebauthnRegistration]) -> Value {
    // Activate/delete responses historically use twoFactorU2f (Vaultwarden-compatible).
    let keys: Vec<Value> = registrations
        .iter()
        .map(WebauthnRegistration::to_client_json)
        .collect();
    serde_json::json!({
        "enabled": enabled,
        "keys": keys,
        "object": "twoFactorU2f",
    })
}

fn relying_party_from_base(base_url: &str) -> Result<webauthn::RelyingParty, AppError> {
    webauthn::RelyingParty::from_base_url(base_url)
}

async fn upsert_twofactor_row(db: &crate::db::Db, twofactor: &TwoFactor) -> Result<(), AppError> {
    d1_query!(
        db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &twofactor.user_uuid,
        twofactor.atype
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    d1_query!(
        db,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &twofactor.uuid,
        &twofactor.user_uuid,
        twofactor.atype,
        twofactor.enabled as i32,
        &twofactor.data,
        twofactor.last_used
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

async fn delete_twofactor_type(
    db: &crate::db::Db,
    user_id: &str,
    atype: TwoFactorType,
) -> Result<(), AppError> {
    d1_query!(
        db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        user_id,
        atype as i32
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub(crate) async fn load_webauthn_registrations(
    db: &crate::db::Db,
    user_id: &str,
) -> Result<(bool, Vec<WebauthnRegistration>), AppError> {
    match find_twofactor(db, user_id, TwoFactorType::Webauthn).await? {
        Some(tf) => Ok((tf.enabled, webauthn_registrations_from_data(&tf.data)?)),
        None => Ok((false, Vec::new())),
    }
}

/// Create a login challenge and persist state (atype 1004). Returns PublicKeyCredentialRequestOptions.
pub(crate) async fn generate_webauthn_login_options(
    db: &crate::db::Db,
    base_url: &str,
    user_id: &str,
) -> Result<Value, AppError> {
    let rp = relying_party_from_base(base_url)?;
    let (_enabled, registrations) = load_webauthn_registrations(db, user_id).await?;
    let (options, state) = webauthn::start_authentication(&rp, &registrations)?;
    let tf = TwoFactor::new(
        user_id.to_string(),
        TwoFactorType::WebauthnLoginChallenge,
        serde_json::to_string(&state).map_err(|_| AppError::Internal)?,
    );
    upsert_twofactor_row(db, &tf).await?;
    Ok(options)
}

/// Validate a WebAuthn assertion for login (`twoFactorToken` JSON).
pub(crate) async fn validate_webauthn_login(
    db: &crate::db::Db,
    base_url: &str,
    user_id: &str,
    assertion_json: &str,
) -> Result<(), AppError> {
    let rp = relying_party_from_base(base_url)?;
    let state_tf = find_twofactor(db, user_id, TwoFactorType::WebauthnLoginChallenge)
        .await?
        .ok_or_else(|| AppError::BadRequest("Can't recover login challenge".to_string()))?;
    let state: LoginChallengeState = serde_json::from_str(&state_tf.data)
        .map_err(|_| AppError::BadRequest("Can't recover login challenge".to_string()))?;
    delete_twofactor_type(db, user_id, TwoFactorType::WebauthnLoginChallenge).await?;

    let (enabled, mut registrations) = load_webauthn_registrations(db, user_id).await?;
    if !enabled || registrations.is_empty() {
        return Err(AppError::BadRequest(
            "WebAuthn 2FA not configured".to_string(),
        ));
    }

    webauthn::finish_authentication(&rp, &state, &mut registrations, assertion_json).await?;

    let data = serde_json::to_string(&registrations).map_err(|_| AppError::Internal)?;
    let tf = TwoFactor::new(user_id.to_string(), TwoFactorType::Webauthn, data);
    upsert_twofactor_row(db, &tf).await?;
    Ok(())
}

/// POST /api/two-factor/get-webauthn
#[worker::send]
pub async fn get_webauthn(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let _rp = relying_party_from_base(&base_url)?;
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    validate_password_or_otp(&user, &data).await?;

    let (enabled, registrations) = load_webauthn_registrations(&db, &user_id).await?;
    Ok(Json(jsonify_webauthn(enabled, &registrations)))
}

/// POST /api/two-factor/get-webauthn-challenge
#[worker::send]
pub async fn get_webauthn_challenge(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let rp = relying_party_from_base(&base_url)?;
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    validate_password_or_otp(&user, &data).await?;

    let (_enabled, registrations) = load_webauthn_registrations(&db, &user_id).await?;
    let exclude: Vec<String> = registrations
        .iter()
        .map(|r| r.credential.cred_id.clone())
        .collect();

    let display_name = user
        .name
        .clone()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| user.email.clone());

    let (options, state) =
        webauthn::start_registration(&rp, &user.id, &user.email, &display_name, &exclude)?;
    let tf = TwoFactor::new(
        user_id.clone(),
        TwoFactorType::WebauthnRegisterChallenge,
        serde_json::to_string(&state).map_err(|_| AppError::Internal)?,
    );
    upsert_twofactor_row(&db, &tf).await?;
    Ok(Json(options))
}

/// POST /api/two-factor/webauthn
#[worker::send]
pub async fn activate_webauthn(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableWebauthnData>,
) -> Result<Json<Value>, AppError> {
    let rp = relying_party_from_base(&base_url)?;
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    validate_password_or_otp(
        &user,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash.clone(),
            otp: data.otp.clone(),
        },
    )
    .await?;

    let slot_id = data.id.into_i32()?;
    if !(1..=5).contains(&slot_id) {
        return Err(AppError::BadRequest(
            "WebAuthn key id must be between 1 and 5".to_string(),
        ));
    }
    if data.name.trim().is_empty() {
        return Err(AppError::BadRequest(
            "WebAuthn key name is required".to_string(),
        ));
    }

    let challenge_tf = find_twofactor(&db, &user_id, TwoFactorType::WebauthnRegisterChallenge)
        .await?
        .ok_or_else(|| AppError::BadRequest("Can't recover challenge".to_string()))?;
    let state: RegisterChallengeState = serde_json::from_str(&challenge_tf.data)
        .map_err(|_| AppError::BadRequest("Can't recover challenge".to_string()))?;
    delete_twofactor_type(&db, &user_id, TwoFactorType::WebauthnRegisterChallenge).await?;

    let credential = webauthn::finish_registration(&rp, &state, &data.device_response)?;

    let (_enabled, mut registrations) = load_webauthn_registrations(&db, &user_id).await?;
    if registrations
        .iter()
        .any(|r| r.credential.cred_id == credential.cred_id)
    {
        return Err(AppError::BadRequest(
            "WebAuthn credential already registered".to_string(),
        ));
    }
    // Replace same slot id if re-registering.
    registrations.retain(|r| r.id != slot_id);
    if registrations.len() >= 5 {
        return Err(AppError::BadRequest(
            "Maximum of 5 WebAuthn keys allowed".to_string(),
        ));
    }
    registrations.push(WebauthnRegistration {
        id: slot_id,
        name: data.name,
        migrated: false,
        credential,
    });
    registrations.sort_by_key(|r| r.id);

    let tf = TwoFactor::new(
        user_id.clone(),
        TwoFactorType::Webauthn,
        serde_json::to_string(&registrations).map_err(|_| AppError::Internal)?,
    );
    upsert_twofactor_row(&db, &tf).await?;
    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(jsonify_webauthn_u2f(true, &registrations)))
}

/// PUT /api/two-factor/webauthn
#[worker::send]
pub async fn activate_webauthn_put(
    env: State<Arc<Env>>,
    base_url: Extension<BaseUrl>,
    auth_user: AuthUser,
    data: Json<EnableWebauthnData>,
) -> Result<Json<Value>, AppError> {
    activate_webauthn(env, base_url, auth_user, data).await
}

/// DELETE /api/two-factor/webauthn
#[worker::send]
pub async fn delete_webauthn(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DeleteWebauthnData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    if !user
        .verify_master_password(&data.master_password_hash)
        .await?
        .is_valid()
    {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    let slot_id = data.id.into_i32()?;
    let Some(tf) = find_twofactor(&db, &user_id, TwoFactorType::Webauthn).await? else {
        return Err(AppError::BadRequest("Webauthn data not found!".to_string()));
    };
    let mut registrations = webauthn_registrations_from_data(&tf.data)?;
    let Some(pos) = registrations.iter().position(|r| r.id == slot_id) else {
        return Err(AppError::BadRequest("Webauthn entry not found".to_string()));
    };
    registrations.remove(pos);

    if registrations.is_empty() {
        delete_twofactor_type(&db, &user_id, TwoFactorType::Webauthn).await?;
        clear_recovery_if_no_twofactor(&db, &user_id).await?;
        return Ok(Json(jsonify_webauthn_u2f(false, &[])));
    }

    let updated = TwoFactor::new(
        user_id.clone(),
        TwoFactorType::Webauthn,
        serde_json::to_string(&registrations).map_err(|_| AppError::Internal)?,
    );
    upsert_twofactor_row(&db, &updated).await?;
    Ok(Json(jsonify_webauthn_u2f(true, &registrations)))
}
