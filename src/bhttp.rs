//! Binary HTTP (RFC 9292) translation between "a binary HTTP request
//! message" (RFC 9458 §4.1's own phrase for what an Encapsulated Request
//! protects) and ordinary HTTP as understood by `reqwest`.
//!
//! Requests may use either the known-length or indeterminate-length form;
//! responses are always written in the known-length form.

use std::collections::HashSet;
use std::io::Cursor;

use bhttp::{Message, Mode, StatusCode};
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

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

fn connection_nominated_headers<'a>(values: impl Iterator<Item = &'a [u8]>) -> HashSet<Vec<u8>> {
    values
        .flat_map(|value| value.split(|byte| *byte == b','))
        .map(|value| value.trim_ascii().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn is_connection_nominated(name: &[u8], nominated: &HashSet<Vec<u8>>) -> bool {
    nominated.contains(&name.to_ascii_lowercase())
}

/// The binary HTTP request message (RFC 9458 §4.1) that an Encapsulated
/// Request protects, decoded into its ordinary-HTTP parts.
pub struct BinaryHttpRequest {
    /// HTTP method, e.g. `GET`.
    pub method: Method,
    /// Request scheme, e.g. `https`. Empty if the BHTTP message omitted it.
    pub scheme: String,
    /// Request authority (`host[:port]`), matched against the allowlist.
    pub authority: String,
    /// Request path, including any query string.
    pub path: String,
    /// Request headers, with hop-by-hop headers and any client-supplied
    /// `Host` and `Content-Length` headers already stripped (the outbound
    /// request always gets its `Host` from the resolved target and its
    /// length from `body`, never from the client).
    pub headers: HeaderMap,
    /// Request body.
    pub body: Vec<u8>,
}

/// Framing indicator of an indeterminate-length request (RFC 9292 §3.2).
const INDETERMINATE_LENGTH_REQUEST: u8 = 2;

/// Decode a BHTTP request
///
/// # Errors
///
/// Returns [`PayloadError::Malformed`] if `bytes` isn't a valid BHTTP
/// request, or any of its header or trailer fields aren't valid HTTP. Returns
/// [`PayloadError::UnsupportedExpectation`] for a 100-continue expectation.
pub fn decode_request(bytes: &[u8]) -> Result<BinaryHttpRequest, PayloadError> {
    // RFC 9292 §3.8 lets a message end after its header section, omitting
    // empty content and trailer sections, but in the indeterminate-length
    // form `bhttp` requires the trailer terminator. Two appended zeros can
    // only terminate the content and trailer sections, and are otherwise
    // read as padding, so a truncated header section is still rejected.
    let padded;
    let bytes = if bytes.first() == Some(&INDETERMINATE_LENGTH_REQUEST) {
        padded = [bytes, &[0, 0]].concat();
        &padded[..]
    } else {
        bytes
    };
    let mut cursor = Cursor::new(bytes);
    let message = Message::read_bhttp(&mut cursor).map_err(|_| PayloadError::Malformed)?;

    let control = message.control();
    if !control.is_request() {
        return Err(PayloadError::Malformed);
    }

    let method_bytes = control.method().ok_or(PayloadError::Malformed)?;
    let method = Method::from_bytes(method_bytes).map_err(|_| PayloadError::Malformed)?;
    let utf8 =
        |bytes: &[u8]| String::from_utf8(bytes.to_vec()).map_err(|_| PayloadError::Malformed);
    let scheme = control.scheme().map(utf8).transpose()?.unwrap_or_default();
    let authority = control
        .authority()
        .filter(|a| !a.is_empty())
        .map(utf8)
        .transpose()?;
    let path = control
        .path()
        .map(utf8)
        .transpose()?
        .unwrap_or_else(|| "/".to_string());

    let connection_nominated = connection_nominated_headers(
        message
            .header()
            .iter()
            .filter(|field| field.name().eq_ignore_ascii_case(b"connection"))
            .map(|field| field.value()),
    );

    // RFC 9292 §4: a message with an invalid field must not be processed,
    // even if that field would be dropped below. Trailers are validated and
    // then discarded because the outbound request carries no trailers.
    let parse_field = |field: &bhttp::Field| {
        Ok::<_, PayloadError>((
            HeaderName::from_bytes(field.name()).map_err(|_| PayloadError::Malformed)?,
            HeaderValue::from_bytes(field.value()).map_err(|_| PayloadError::Malformed)?,
        ))
    };
    for field in message.trailer().iter() {
        parse_field(field)?;
    }

    let mut headers = HeaderMap::new();
    let mut host_header_values: Vec<HeaderValue> = Vec::new();
    for field in message.header().iter() {
        let (name, value) = parse_field(field)?;
        // RFC 9458 §5.1 forbids this handshake inside an encapsulated request.
        // Check before removing connection-specific fields.
        if name == reqwest::header::EXPECT
            && value
                .as_bytes()
                .split(|b| *b == b',')
                .any(|value| value.trim_ascii().eq_ignore_ascii_case(b"100-continue"))
        {
            return Err(PayloadError::UnsupportedExpectation);
        }
        if is_hop_by_hop(field.name())
            || is_connection_nominated(field.name(), &connection_nominated)
        {
            continue;
        }
        // Never forward the client's own Host header: the outbound request
        // always goes to the (allowlist-checked) authority/rewrite target,
        // and letting a client-supplied Host reach the target verbatim
        // would let it request a different virtual host than the one the
        // operator actually allowlisted, even though the TCP destination is
        // correct. `reqwest`/hyper set the wire Host header from the
        // request URL when none is explicitly provided, which is what we
        // want here. Collected separately for the origin-form fallback
        // below, not appended to `headers`.
        if name == reqwest::header::HOST {
            host_header_values.push(value);
            continue;
        }
        // The outbound body is `message.content()`, so the HTTP client
        // derives the framing from it; a client-supplied length could
        // disagree with those bytes.
        if name == reqwest::header::CONTENT_LENGTH {
            continue;
        }
        // `HeaderMap::append` panics once the map reaches its maximum size,
        // which a 2 MiB request of short fields can exceed.
        headers
            .try_append(name, value)
            .map_err(|_| PayloadError::Malformed)?;
    }

    // RFC 9292 permits an empty authority when the destination is in Host.
    let authority = match authority {
        Some(authority) => authority,
        None => {
            let mut hosts = host_header_values.iter();
            let host = hosts
                .next()
                .ok_or(PayloadError::Malformed)?
                .to_str()
                .map_err(|_| PayloadError::Malformed)?;
            if host.is_empty() || hosts.next().is_some() {
                return Err(PayloadError::Malformed);
            }
            host.to_string()
        }
    };

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
/// known-length BHTTP response
///
/// # Panics
///
/// Never in practice: the only fallible step falls back to a hardcoded
/// `500`, which is always a valid BHTTP status code.
#[must_use]
pub fn encode_response(status: u16, headers: &HeaderMap, body: &[u8]) -> Vec<u8> {
    let status_code = StatusCode::try_from(status).unwrap_or_else(|_| {
        StatusCode::try_from(500u16).expect("500 is a valid BHTTP status code")
    });
    let mut message = Message::response(status_code);
    let connection_nominated = connection_nominated_headers(
        headers
            .get_all(reqwest::header::CONNECTION)
            .iter()
            .map(reqwest::header::HeaderValue::as_bytes),
    );
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str().as_bytes())
            || is_connection_nominated(name.as_str().as_bytes(), &connection_nominated)
        {
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

#[cfg(test)]
mod tests {
    use super::{decode_request, encode_response};
    use crate::error::PayloadError;
    use bhttp::{Message, Mode};
    use reqwest::header::{HeaderMap, HeaderValue};

    fn encode(request: &Message) -> Vec<u8> {
        let mut encoded = Vec::new();
        request
            .write_bhttp(Mode::KnownLength, &mut encoded)
            .unwrap();
        encoded
    }

    #[test]
    fn client_content_length_is_not_forwarded() {
        let mut request = Message::request(
            b"POST".to_vec(),
            b"https".to_vec(),
            b"allowed.example".to_vec(),
            b"/".to_vec(),
        );
        request.put_header(b"content-length".to_vec(), b"100".to_vec());
        request.write_content(b"hello");

        let decoded = decode_request(&encode(&request)).unwrap();
        assert!(!decoded.headers.contains_key("content-length"));
        assert_eq!(decoded.body, b"hello");
    }

    fn request() -> Message {
        Message::request(
            b"POST".to_vec(),
            b"https".to_vec(),
            b"allowed.example".to_vec(),
            b"/".to_vec(),
        )
    }

    #[test]
    fn truncated_indeterminate_length_requests_are_decoded() {
        let mut empty = Vec::new();
        request()
            .write_bhttp(Mode::IndeterminateLength, &mut empty)
            .unwrap();
        // Header terminator, empty content, then empty trailer terminator.
        assert!(empty.ends_with(&[0, 0, 0]));
        for omitted in [1, 2] {
            let decoded = decode_request(&empty[..empty.len() - omitted]).unwrap();
            assert_eq!(decoded.authority, "allowed.example", "omitted {omitted}");
            assert!(decoded.body.is_empty());
        }
        assert!(matches!(
            decode_request(&empty[..empty.len() - 3]),
            Err(PayloadError::Malformed)
        ));

        let mut with_content = request();
        with_content.write_content(b"hi");
        let mut encoded = Vec::new();
        with_content
            .write_bhttp(Mode::IndeterminateLength, &mut encoded)
            .unwrap();
        for omitted in [1, 2] {
            let decoded = decode_request(&encoded[..encoded.len() - omitted]).unwrap();
            assert_eq!(decoded.body, b"hi", "omitted {omitted}");
        }
    }

    #[test]
    fn invalid_fields_are_malformed_even_when_they_would_be_dropped() {
        let mut hop_by_hop_crlf = request();
        hop_by_hop_crlf.put_header(b"te".to_vec(), b"x\r\nx-injected: 1".to_vec());
        let mut nominated_pseudo_field = request();
        nominated_pseudo_field.put_header(b"connection".to_vec(), b":method".to_vec());
        nominated_pseudo_field.put_header(b":method".to_vec(), b"DELETE".to_vec());
        let mut trailer_nul = request();
        trailer_nul.put_trailer(b"x-trailer".to_vec(), b"a\0b".to_vec());

        for (case, message) in [
            ("hop-by-hop CRLF", hop_by_hop_crlf),
            ("connection-nominated pseudo-field", nominated_pseudo_field),
            ("trailer NUL", trailer_nul),
        ] {
            assert!(
                matches!(
                    decode_request(&encode(&message)),
                    Err(PayloadError::Malformed)
                ),
                "{case}"
            );
        }
    }

    #[test]
    fn too_many_header_fields_are_malformed() {
        let mut message = request();
        for i in 0..=32_768 {
            message.put_header(format!("x-{i}").into_bytes(), b"1".to_vec());
        }
        assert!(matches!(
            decode_request(&encode(&message)),
            Err(PayloadError::Malformed)
        ));
    }

    #[test]
    fn invalid_utf8_control_fields_are_malformed() {
        let valid = [
            b"https".to_vec(),
            b"allowed.example".to_vec(),
            b"/".to_vec(),
        ];
        for field in 0..valid.len() {
            let mut parts = valid.clone();
            parts[field] = b"/\xff".to_vec();
            let [scheme, authority, path] = parts;
            let request = Message::request(b"GET".to_vec(), scheme, authority, path);
            assert!(
                matches!(
                    decode_request(&encode(&request)),
                    Err(PayloadError::Malformed)
                ),
                "control field {field}"
            );
        }
    }

    #[test]
    fn connection_nominated_headers_do_not_cross_the_gateway_boundary() {
        let mut request = Message::request(
            b"GET".to_vec(),
            b"https".to_vec(),
            b"allowed.example".to_vec(),
            b"/".to_vec(),
        );
        request.put_header(b"connection".to_vec(), b"x-hop".to_vec());
        request.put_header(b"x-hop".to_vec(), b"private".to_vec());
        request.put_header(b"x-keep".to_vec(), b"public".to_vec());
        let mut encoded = Vec::new();
        request
            .write_bhttp(Mode::KnownLength, &mut encoded)
            .unwrap();

        let decoded = decode_request(&encoded).unwrap();
        assert!(!decoded.headers.contains_key("x-hop"));
        assert_eq!(decoded.headers["x-keep"], "public");

        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("x-hop"));
        headers.insert("x-hop", HeaderValue::from_static("private"));
        headers.insert("x-keep", HeaderValue::from_static("public"));
        let encoded = encode_response(200, &headers, b"");
        let response = Message::read_bhttp(&mut std::io::Cursor::new(encoded)).unwrap();
        assert_eq!(response.control().status().unwrap().code(), 200);
        assert!(
            response
                .header()
                .iter()
                .all(|field| !field.name().eq_ignore_ascii_case(b"connection")
                    && !field.name().eq_ignore_ascii_case(b"x-hop"))
        );
        assert!(
            response
                .header()
                .iter()
                .any(|field| field.name().eq_ignore_ascii_case(b"x-keep"))
        );
    }
}
