use serde::{Deserialize, Serialize};

/// Two-factor authentication types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TwoFactorType {
    Authenticator = 0, // TOTP
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    Webauthn = 7,
    RecoveryCode = 8,
    /// Pending email ownership proof before Email 2FA is enabled (excluded from lists).
    EmailVerificationChallenge = 1000,
}

impl TwoFactorType {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(TwoFactorType::Authenticator),
            1 => Some(TwoFactorType::Email),
            2 => Some(TwoFactorType::Duo),
            3 => Some(TwoFactorType::YubiKey),
            4 => Some(TwoFactorType::U2f),
            5 => Some(TwoFactorType::Remember),
            6 => Some(TwoFactorType::OrganizationDuo),
            7 => Some(TwoFactorType::Webauthn),
            8 => Some(TwoFactorType::RecoveryCode),
            1000 => Some(TwoFactorType::EmailVerificationChallenge),
            _ => None,
        }
    }
}

/// JSON blob stored in `twofactor.data` for Email / EmailVerificationChallenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailTokenData {
    pub email: String,
    pub last_token: Option<String>,
    pub token_sent: i64,
    pub attempts: u64,
}

impl EmailTokenData {
    pub const TOKEN_DIGITS: usize = 6;
    pub const EXPIRATION_SECS: i64 = 600;
    pub const ATTEMPTS_LIMIT: u64 = 3;

    pub fn new(email: String, token: String) -> Self {
        Self {
            email,
            last_token: Some(token),
            token_sent: chrono::Utc::now().timestamp(),
            attempts: 0,
        }
    }

    pub fn set_token(&mut self, token: String) {
        self.last_token = Some(token);
        self.token_sent = chrono::Utc::now().timestamp();
        self.attempts = 0;
    }

    pub fn reset_token(&mut self) {
        self.last_token = None;
        self.attempts = 0;
    }

    pub fn add_attempt(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }

    pub fn to_json(&self) -> Result<String, crate::error::AppError> {
        serde_json::to_string(self).map_err(|_| crate::error::AppError::Internal)
    }

    pub fn from_json(s: &str) -> Result<Self, crate::error::AppError> {
        serde_json::from_str(s).map_err(|_| {
            crate::error::AppError::BadRequest("Could not decode email 2FA data".to_string())
        })
    }
}

/// POST /api/two-factor/send-email
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailData {
    pub email: String,
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

/// PUT /api/two-factor/email
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateEmailData {
    pub email: String,
    pub token: String,
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

/// POST /api/two-factor/send-email-login (unauthenticated)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailLoginData {
    pub email: Option<String>,
    pub master_password_hash: Option<String>,
    pub device_identifier: Option<String>,
}

/// TwoFactor database model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactor {
    pub uuid: String,
    pub user_uuid: String,
    pub atype: i32,
    #[serde(with = "bool_from_int")]
    pub enabled: bool,
    pub data: String,
    pub last_used: i64,
}

impl TwoFactor {
    pub fn new(user_uuid: String, atype: TwoFactorType, data: String) -> Self {
        Self {
            uuid: uuid::Uuid::new_v4().to_string(),
            user_uuid,
            atype: atype as i32,
            enabled: true,
            data,
            last_used: 0,
        }
    }

    pub fn to_json_provider(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "type": self.atype,
            "object": "twoFactorProvider"
        })
    }
}

mod bool_from_int {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(serde::de::Error::custom("expected integer 0 or 1")),
        }
    }

    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if *value {
            serializer.serialize_i64(1)
        } else {
            serializer.serialize_i64(0)
        }
    }
}

/// POST /api/two-factor/authenticator - Enable TOTP
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorData {
    pub key: String,
    pub token: String,
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableTwoFactorData {
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i32,
}

/// DELETE /api/two-factor/authenticator - Disable TOTP with key verification
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableAuthenticatorData {
    pub key: String,
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i32,
}
