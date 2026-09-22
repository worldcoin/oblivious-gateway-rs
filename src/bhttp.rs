//! Binary HTTP (RFC 9292) translation between "a binary HTTP request
//! message" (RFC 9458 §4.1's own phrase for what an Encapsulated Request
//! protects) and ordinary HTTP as understood by `reqwest`.
//!
//! Known-length framing is used on both directions, matching the Go
//! reference's `ohttp.UnmarshalBinaryRequest` / `ohttp.CreateBinaryResponse`,
//! which also use RFC 9292's known-length message format.

use std::io::Cursor;

use bhttp::{Message, Mode, StatusCode};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;

use crate::error::PayloadError;

/// Hop-by-hop headers (RFC 7230 §6.1) are connection-specific and must not
/// be forwarded across the gateway boundary in either direction.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &[u8]) -> bool {
    HOP_BY_HOP
        .iter()
        .any(|h| h.as_bytes().eq_ignore_ascii_case(name))
}

/// The binary HTTP request message (RFC 9458 §4.1) that an Encapsulated
/// Request protects, decoded into its ordinary-HTTP parts.
pub struct BinaryHttpRequest {
    pub method: Method,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// Decode a known-length BHTTP request, matching RFC 9292 §3.3 / Go's
/// `ohttp.UnmarshalBinaryRequest`.
pub fn decode_request(bytes: &[u8]) -> Result<BinaryHttpRequest, PayloadError> {
    let mut cursor = Cursor::new(bytes);
    let message = Message::read_bhttp(&mut cursor).map_err(|_| PayloadError::Malformed)?;

    let control = message.control();
    if !control.is_request() {
        return Err(PayloadError::Malformed);
    }

    let method_bytes = control.method().ok_or(PayloadError::Malformed)?;
    let method = Method::from_bytes(method_bytes).map_err(|_| PayloadError::Malformed)?;
    let scheme = control
        .scheme()
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .unwrap_or_default();
    let authority = control
        .authority()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .ok_or(PayloadError::Malformed)?;
    let path = control
        .path()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_else(|| "/".to_string());

    let mut headers = HeaderMap::new();
    for field in message.header().iter() {
        if is_hop_by_hop(field.name()) {
            continue;
        }
        let name = HeaderName::from_bytes(field.name()).map_err(|_| PayloadError::Malformed)?;
        let value = HeaderValue::from_bytes(field.value()).map_err(|_| PayloadError::Malformed)?;
        headers.append(name, value);
    }

    Ok(BinaryHttpRequest {
        method,
        scheme,
        authority,
        path,
        headers,
        body: message.content().to_vec(),
    })
}

/// Encode an ordinary HTTP status/headers/body triple back into a
/// known-length BHTTP response, matching Go's `ohttp.CreateBinaryResponse`.
pub fn encode_response(status: u16, headers: &HeaderMap, body: &[u8]) -> Vec<u8> {
    let status_code = StatusCode::try_from(status).unwrap_or_else(|_| {
        StatusCode::try_from(500u16).expect("500 is a valid BHTTP status code")
    });
    let mut message = Message::response(status_code);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str().as_bytes()) {
            continue;
        }
        message.put_header(name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec());
    }
    message.write_content(body);

    let mut out = Vec::new();
    message
        .write_bhttp(Mode::KnownLength, &mut out)
        .expect("writing to an in-memory buffer cannot fail");
    out
}

/// Build a minimal known-length BHTTP error response with a plain-text body,
/// used when the gateway must report a payload-level failure (malformed
/// request, forbidden target, upstream failure) inside the encrypted
/// response while the outer HTTP status stays 200.
pub fn encode_error_response(status: u16, message: &str) -> Vec<u8> {
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    encode_response(status, &headers, message.as_bytes())
}
