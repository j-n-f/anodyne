use std::collections::HashMap;

use axum::extract::Request;

use crate::session::SessionError;

/// Print a hexdump with some width and a label
pub fn annotated_hex_dump(label: &str, bytes: &[u8], max_octets: Option<usize>, show_addr: bool) {
    let width = max_octets.unwrap_or(bytes.len());

    // TODO: should be trace log
    println!("{} [{}]:", label, bytes.len());
    for (line_number, chunk) in bytes.chunks(width).enumerate() {
        let offset = line_number * width;
        // TODO: should be trace log
        println!(
            "    {}{}",
            show_addr
                .then(|| format!("{offset:04x} | "))
                .unwrap_or_default(),
            hex_dump(chunk)
        );
    }
}

/// Turn a byte slice into space-separated hex octets
#[must_use]
pub fn hex_dump(x: &[u8]) -> String {
    x.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Stores cookies on incoming requests
#[derive(Debug, Default)]
pub struct CookieJar<'a> {
    cookies: HashMap<&'a str, &'a str>,
}

impl<'a> CookieJar<'a> {
    /// Parse a `CookieJar` from a request.
    ///
    /// # Errors
    ///
    /// * `SessionError::CookieDecodeFailed` - when cookie fails to decode.
    pub fn from_request(request: &'a Request) -> Result<Self, SessionError> {
        let Some(cookie_header) = request.headers().get(axum::http::header::COOKIE) else {
            // Okay for header to be missing, it just means we have no cookies
            return Ok(CookieJar::default());
        };
        let Ok(header_value) = cookie_header.to_str() else {
            // Header is present, but corrupted somehow
            return Err(SessionError::CookieDecodeFailed("unreadable header".into()));
        };

        let Ok(cookie_jar) = header_value.try_into() else {
            return Err(SessionError::CookieDecodeFailed("unparsable header".into()));
        };

        Ok(cookie_jar)
    }

    /// Get a cookie with some name (names are normalized to be all lowercase)
    #[must_use]
    pub fn get_cookie_named(&self, name: &str) -> Option<&'a str> {
        self.cookies.get(name).copied()
    }
}

impl<'a> TryFrom<&'a str> for CookieJar<'a> {
    // TODO: better error type
    type Error = ();

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            // TODO: get rid of this pointless allocation in case there are no cookies
            return Ok(CookieJar {
                cookies: HashMap::new(),
            });
        }

        let mut cookies = HashMap::new();

        for cookie in cookie::Cookie::split_parse(value) {
            let cookie = match cookie {
                Ok(cookie) => cookie,
                Err(cookie_error) => {
                    eprintln!("cookie parse error: {cookie_error}");
                    return Err(());
                }
            };
            let Some(cookie_name) = cookie.name_raw() else {
                return Err(());
            };
            let Some(cookie_value) = cookie.value_raw() else {
                return Err(());
            };

            if cookies.try_insert(cookie_name, cookie_value).is_err() {
                // TODO: determine if this is actually an error, or if the last value is supposed to
                //       take precedence.
                eprintln!("duplicate cookie key");
                return Err(());
            }
        }

        Ok(CookieJar { cookies })
    }
}

/// For errors that have no clear way to recover; note that the content may be user-visible so avoid
/// leaking sensitive details.
macro_rules! server_error {
    ($error:expr) => {{
        #[allow(unused)]
        use axum::response::IntoResponse;
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, $error).into_response()
    }};
}

pub(crate) use server_error;
