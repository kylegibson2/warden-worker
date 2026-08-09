//! Outbound email via Resend (https://resend.com).
//!
//! Secrets:
//! - `RESEND_API_KEY` — Resend API key
//! - `RESEND_EMAIL_SEND` — verified From address (e.g. `noreply@example.com`)

use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Fetch, Method, Request, RequestInit};

use crate::error::AppError;

const RESEND_API_URL: &str = "https://api.resend.com/emails";

fn secret_string(env: &Env, name: &str) -> Result<String, AppError> {
    let value = env.secret(name).map_err(|_| {
        AppError::BadRequest(format!(
            "Missing Worker secret `{name}`. Set it with `wrangler secret put {name}`."
        ))
    })?;
    Ok(value.to_string())
}

/// Send a plain-text (and simple HTML) email through Resend.
pub async fn send_email(env: &Env, to: &str, subject: &str, text: &str) -> Result<(), AppError> {
    let api_key = secret_string(env, "RESEND_API_KEY")?;
    let from = secret_string(env, "RESEND_EMAIL_SEND")?;

    let html = format!("<p>{}</p>", html_escape(text));
    let body = serde_json::to_string(&json!({
        "from": from,
        "to": [to],
        "subject": subject,
        "text": text,
        "html": html,
    }))
    .map_err(|_| AppError::Internal)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(JsValue::from_str(&body)));

    let mut req = Request::new_with_init(RESEND_API_URL, &init).map_err(AppError::Worker)?;
    let headers = req.headers_mut().map_err(AppError::Worker)?;
    headers
        .set("Content-Type", "application/json")
        .map_err(AppError::Worker)?;
    headers
        .set("Authorization", &format!("Bearer {api_key}"))
        .map_err(AppError::Worker)?;

    let mut response = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    let status = response.status_code();
    if !(200..300).contains(&status) {
        let err_body = response.text().await.unwrap_or_default();
        log::error!("Resend send failed status={status} body={err_body}");
        return Err(AppError::BadRequest(
            "Failed to send email. Check Resend API key, From address, and domain verification."
                .to_string(),
        ));
    }
    Ok(())
}

pub async fn send_two_factor_token(env: &Env, to: &str, token: &str) -> Result<(), AppError> {
    let subject = "Your login verification code";
    let text = format!(
        "Your verification code is: {token}\n\nThis code expires in 10 minutes. If you did not attempt to sign in, you can ignore this email."
    );
    send_email(env, to, subject, &text).await
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', "<br/>")
}
