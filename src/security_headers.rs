//! Shared HTTP security headers for API responses.
//!
//! Static assets get the same headers via `public/_headers` (copied into the
//! web vault during build). Keep both in sync.

use axum::http::{header, HeaderName, HeaderValue};
use tower_http::set_header::SetResponseHeaderLayer;

pub const HSTS: &str = "max-age=31536000; includeSubDomains";
pub const X_CONTENT_TYPE_OPTIONS: &str = "nosniff";
pub const X_FRAME_OPTIONS: &str = "DENY";
pub const REFERRER_POLICY: &str = "no-referrer";

fn header_value(value: &'static str) -> HeaderValue {
    HeaderValue::from_static(value)
}

/// Response-header layers applied to the axum API router.
pub fn layers() -> (
    SetResponseHeaderLayer<HeaderValue>,
    SetResponseHeaderLayer<HeaderValue>,
    SetResponseHeaderLayer<HeaderValue>,
    SetResponseHeaderLayer<HeaderValue>,
) {
    (
        SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            header_value(HSTS),
        ),
        SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            header_value(X_CONTENT_TYPE_OPTIONS),
        ),
        SetResponseHeaderLayer::overriding(header::X_FRAME_OPTIONS, header_value(X_FRAME_OPTIONS)),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            header_value(REFERRER_POLICY),
        ),
    )
}
