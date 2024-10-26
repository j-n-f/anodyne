use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    extract::{ConnectInfo, Request},
    http::HeaderValue,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, RequestExt,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{generic_array::typenum::Unsigned, Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Newtype wrapper around session UUID
#[derive(Clone, Debug)]
pub struct SessionUuid(pub Uuid);

/// A base64-encoded session cookie
#[derive(Clone, Debug)]
pub(crate) struct OutgoingSessionToken(pub String);

// TODO: some kind of FromRequestParts extractor for session so that I don't have to do so much
//       verbose nonsense, and can make use of Axum's infra

/// Given some request, add an extension for getting the session UUID of the current request.
async fn load_or_create_session(
    request: &mut Request,
) -> Result<Option<OutgoingSessionToken>, SessionError> {
    let mut eventual_uuid: Option<Uuid> = None;

    let headers = request.headers().clone();

    let cookies_rx: crate::util::CookieJar = headers
        .get(axum::http::header::COOKIE)
        .map(|hv| hv.to_str().unwrap())
        .unwrap_or_default()
        .try_into()
        .expect("couldn't parse cookies");

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .map(|hv| HeaderValue::to_str(hv).unwrap().to_string())
        .expect("no user agent");

    let client_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied()
        .unwrap();

    let Extension(session_table) = request
        .extract_parts::<Extension<Arc<Mutex<SessionTable>>>>()
        .await
        .unwrap();

    let mut locked_session_table = session_table.lock().await;

    // First see if the user provided a UUID in the cookie
    let encrypted_session_cookie = cookies_rx.get_cookie_named("session");
    if let Some(encrypted_session_cookie) = encrypted_session_cookie {
        if let Ok(uuid) = SessionTable::get_session_uuid_from_cookie(encrypted_session_cookie) {
            // TODO: below prints should be trace logs
            //println!("load_or_create: uuid = {uuid}");

            // If it's in the session store we can continue using it, otherwise we're going to have
            // to generate a new one
            if locked_session_table.sessions.contains_key(&uuid) {
                //println!("load_or_create:   > found in table, will reuse");
                eventual_uuid = Some(uuid);
            } else {
                //println!("load_or_create:   > wasn't in table, will generate new");
            }
        } else {
            //println!("load_or_create: no cookie found");
        }
    }

    if let Some(eventual_uuid) = eventual_uuid {
        // Otherwise, we had a token, and we'll just keep using that
        request.extensions_mut().insert(SessionUuid(eventual_uuid));
        // early return
        return Ok(None);
    }

    // If none was provided in the cookie then we have to create a session, and provide that
    // UUID as an extension so later stages can reference the value.
    let new_session_id = Uuid::new_v4();
    let new_session = Session {
        uuid: new_session_id,
        user_id: None,
        started_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now()
            .checked_add_days(chrono::Days::new(1))
            .unwrap(),
        revoked_at: None,
        revoked_by_user_id: None,
        fingerprint: SessionFingerprint {
            user_agent,
            ip_address: Some(client_ip.ip()),
        },
        data: SessionDataStore::default(),
    };

    let outgoing_base64: OutgoingSessionToken = match new_session.as_cookie() {
        Ok(cookie) => OutgoingSessionToken(cookie),
        Err(session_err) => return Err(session_err),
    };

    // Add any newly created session to the global table
    locked_session_table.insert_session(new_session)?;

    // Add an extension to this request so later middleware can access the new/existing session UUID
    request.extensions_mut().insert(SessionUuid(new_session_id));

    // Drop the global session table to avoid blocking other requests
    drop(locked_session_table);

    // This will be either a new or existing session cookie
    Ok(Some(outgoing_base64))
}

pub async fn session_management_middleware(mut request: Request, next: Next) -> Response {
    // TODO: This function 1) loads the session uuid as an extension, 2) returns the UUID
    //       It should probably just be broken into its own middleware so that we can just use the
    //       extractor in this function (i.e. as part of the signature to
    //       `session_management_middleware`)
    let outgoing_token = load_or_create_session(&mut request).await;

    let mut response = next.run(request).await;

    // This convoluted logic is because we only want to send Set-Cookie the first time we generate
    // a new session.
    if let Ok(Some(outgoing_token)) = outgoing_token {
        let Ok(header_value) =
            HeaderValue::from_str(&format!("session={}; HttpOnly", outgoing_token.0))
        else {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };

        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, header_value);
    }

    response
}

/// Session UUIDs should be sufficient to identify sessions uniquely, but this metadata might e.g.
/// help identify hijacked cookies being used from different IPs/browsers.
#[derive(Default, Debug)]
pub struct SessionFingerprint {
    #[allow(unused)]
    user_agent: String,
    #[allow(unused)]
    ip_address: Option<IpAddr>,
}

/// Metadata for a session.
#[derive(Debug)]
pub struct Session {
    // 16 bytes
    /// UUID uniquely identifying a session.
    uuid: uuid::Uuid,
    /// User id if any, field will get updated if an existing session becomes authenticated.
    user_id: Option<i64>,
    /// Date/time session was started.
    #[allow(unused)]
    started_at: chrono::DateTime<chrono::Utc>,
    /// Date/time session will expire; forced expiration will move this timestamp to now.
    #[allow(unused)]
    expires_at: chrono::DateTime<chrono::Utc>,
    /// Date/time at which a session was revoked. `revoked_by_user_id` should be filled when this
    /// is done.
    #[allow(unused)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// User id who revoked a session, could be the user themselves or an administrator.
    #[allow(unused)]
    revoked_by_user_id: Option<i64>,
    /// Extra metadata associated with a session. Can be used to detect hijacking attempts.
    #[allow(unused)]
    fingerprint: SessionFingerprint,

    // TODO: generalize this a little more so that other details can be stored. Probably a system
    //       like axum's `Extension` mechanism.
    /// Referer(method, route) -> (refill values, map of name -> errors)
    pub data: SessionDataStore,
}

/// Uniquely identifies a route in the application.
pub type RouteKey = (axum::http::Method, String);
/// Data associated with some route by the form validation mechanism for a single session.
pub type RouteData = (
    // Refill values
    // TODO: maybe bytes in the future if flatbuffer works
    String,
    // Errors
    HashMap<&'static str, Vec<&'static str>>,
);

/// Data associated with a session.
#[derive(Debug, Default)]
pub struct SessionDataStore {
    route_store: HashMap<RouteKey, RouteData>,
}

/// Errors related to sessions.
#[derive(Debug, Default)]
pub enum SessionError {
    /// Tried to create a session which already exists
    SessionAlreadyExists,
    /// Failed to insert data related to a session
    DataInsertFailed,
    /// Failed to generate a cookie to represent the session
    CookieGenerationFailed(String),
    /// Failed to decode an encrypted cookie
    CookieDecodeFailed(String),
    #[default]
    Unknown,
}

impl SessionDataStore {
    /// Inserts value for some route, overwriting any existing values
    ///
    /// # Errors
    ///
    /// * In the future this may return `SessionStoreError::InsertFailed`, but for now it's backed
    ///   by a `HashMap` and should always succeed.
    pub fn update_data(
        &mut self,
        route_key: RouteKey,
        data: RouteData,
    ) -> Result<(), SessionError> {
        self.route_store.insert(route_key, data);
        Ok(())
    }

    /// Clears value for some route. Returns `Ok` if value doesn't exist (as this would happen if
    /// the user successfully filled a form on the first try).
    ///
    /// # Errors
    ///
    /// * May return `SessionStoreError::ClearFailed` in the future, but for now it's backed by a
    ///   `HashMap` and should always succeed.
    pub fn clear_data(&mut self, route_key: &RouteKey) -> Result<(), SessionError> {
        self.route_store.remove(route_key);
        Ok(())
    }

    #[must_use]
    pub fn route_data(&self, route_key: &RouteKey) -> Option<&RouteData> {
        self.route_store.get(route_key)
    }
}

impl Session {
    /// Convert a session into a cookie.
    ///
    /// # Errors
    ///
    /// * `SessionError::CookieGenerationFailed` if encryption fails.
    pub fn as_cookie(&self) -> Result<String, SessionError> {
        let mut bytes: Vec<u8> = vec![];

        // 16 bytes user-specific data (prevent unlikely collisions in UUIDs)
        // ?? bytes expiry timestamp (after this the cookie is no good)
        //  4 bytes sequence number
        // 16 bytes session UUID
        // ~~32 bytes HMAC~~ (this is redundant with AEAD)
        //
        // All values in big-endian (network order)

        // User ID (0 if unauthenticated)
        bytes.extend_from_slice(&self.user_id.unwrap_or_default().to_be_bytes());
        // TODO: expiry timestamp
        // 4-byte sequence number
        // TODO: remove this field, deprecated
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        // Reserved (zero-pad)
        bytes.extend_from_slice(&0_i64.to_be_bytes());

        // Session UUID
        bytes.extend_from_slice(self.uuid.as_bytes());

        // TODO: load an actual key from configuration
        let dummy_app_key = (0..32_u8).collect::<Vec<_>>();

        // TODO: app key should be rotated at regular intervals, there will need to be a way for
        //       sessions to survive key rotations. Per-session encryption wrapped in global
        //       encryption?

        // Encrypt with application key
        let key = chacha20poly1305::Key::from_slice(&dummy_app_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, bytes.as_ref()).map_err(|err| {
            SessionError::CookieGenerationFailed(format!("couldn't encrypt cookie: {err}"))
        })?;

        // TODO: work out the size for this to avoid wasted space; should account for different
        //       cryptography options
        let mut out_buffer = String::with_capacity(96);

        STANDARD.encode_string(nonce, &mut out_buffer);
        STANDARD.encode_string(&ciphertext, &mut out_buffer);

        // TODO: convert these to traces
        //println!("encryption -------------");
        //crate::util::annotated_hex_dump("nonce", &nonce, Some(32), true);
        //crate::util::annotated_hex_dump("ciphertext", &ciphertext, Some(32), true);
        //crate::util::annotated_hex_dump("output base64", out_buffer.as_bytes(), Some(32), true);

        Ok(out_buffer)
    }
}

// TODO: create a trait to represent a session store that can be distributed between instances and
//       survive restarts.
/// A global table of all session data.
#[derive(Debug, Default)]
pub struct SessionTable {
    sessions: HashMap<uuid::Uuid, Session>,
}

impl SessionTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// Insert a session into the global table.
    ///
    /// # Errors
    ///
    /// * `SessionError::SessionAlreadyExists` if the UUID is already in the table. Could be a
    ///   collision, or the caller tried to insert twice.
    pub fn insert_session(&mut self, session: Session) -> Result<(), SessionError> {
        match self.sessions.try_insert(session.uuid, session) {
            Ok(_old_session_data) => Ok(()),
            Err(_e) => Err(SessionError::SessionAlreadyExists),
        }
    }

    /// Returns a mutable reference to a session if it exists.
    pub fn session_mut(&mut self, uuid: &Uuid) -> Option<&mut Session> {
        self.sessions.get_mut(uuid)
    }

    /// Get information necessary to identify a session from a base64-encoded cookie.
    ///
    /// # Errors
    ///
    /// * `SessionError::CookieDecodeFailed` - error will contain details on specifically what
    ///   failed.
    pub fn get_session_uuid_from_cookie(base64: &str) -> Result<Uuid, SessionError> {
        let mut decoded_bytes = [0_u8; 64];
        let total_decoded_bytes = match STANDARD.decode_slice(base64, &mut decoded_bytes) {
            Err(_) => {
                return Err(SessionError::CookieDecodeFailed(
                    "base64 decode failed".into(),
                ))
            }
            Ok(bytes_written) => {
                // TODO: trace log
                //println!("wrote {bytes_written} bytes while decoding");
                bytes_written
            }
        };

        // TODO: fetch this key from config
        let dummy_app_key = (0..32_u8).collect::<Vec<_>>();

        // Try finding this in the docs. Holy crow.
        let nonce_size = <ChaCha20Poly1305 as AeadCore>::NonceSize::USIZE;

        // Decrypt with application key
        let (nonce, padded_ciphertext) = decoded_bytes.split_at(nonce_size);
        let (ciphertext, _) = padded_ciphertext.split_at(total_decoded_bytes - nonce_size);

        // TODO: convert these to traces
        //println!("decryption -------------");
        //println!("input base64 [{}]", base64.len());
        //println!("    {base64}");
        //crate::util::annotated_hex_dump("decoded bytes", &decoded_bytes, Some(32), true);
        //crate::util::annotated_hex_dump("nonce", nonce, Some(32), true);
        //crate::util::annotated_hex_dump("ciphertext", ciphertext, Some(32), true);

        let key = chacha20poly1305::Key::from_slice(&dummy_app_key);
        let cipher = ChaCha20Poly1305::new(key);
        let decrypted_bytes = cipher
            .decrypt(nonce.into(), ciphertext)
            .inspect_err(|&err| {
                eprintln!("decryption error: {err:#?}");
            });

        let Ok(decrypted_bytes) = decrypted_bytes else {
            return Err(SessionError::CookieDecodeFailed("failed to decrypt".into()));
        };

        // deserialize

        // skip 16 bytes to get sequence number
        // TODO: will change once expiry timestamp is added
        let Ok(sequence_bytes) = decrypted_bytes[16..20].try_into() else {
            return Err(SessionError::CookieDecodeFailed(
                "failed to decode sequence number".into(),
            ));
        };
        let _sequence: u32 = u32::from_be_bytes(sequence_bytes);

        let Ok(uuid_bytes) = decrypted_bytes[20..36].try_into() else {
            return Err(SessionError::CookieDecodeFailed(
                "failed to decode session uuid".into(),
            ));
        };
        let uuid: Uuid = Uuid::from_bytes(uuid_bytes);

        Ok(uuid)
    }
}
