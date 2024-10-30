use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::extract::{ConnectInfo, Request};
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

// TODO: some kind of FromRequestParts extractor for session so that I don't have to do so much
//       verbose nonsense, and can make use of Axum's infra

/// Session UUIDs should be sufficient to identify sessions uniquely, but this metadata might e.g.
/// help identify hijacked cookies being used from different IPs/browsers.
#[derive(Default, Debug)]
pub struct SessionFingerprint {
    #[allow(unused)]
    user_agent: Option<String>,
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
    /// Failed to create a new session
    SessionCreationError(String),
    /// Tried to create a session which already exists
    SessionAlreadyExists,
    /// Failed to insert data related to a session
    DataInsertFailed,
    /// Failed to generate a cookie to represent the session
    CookieGenerationFailed(String),
    /// Failed to decode an encrypted cookie
    CookieDecodeFailed(String),
    /// Failed to get a handle to the session store
    StoreUnavailable,
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
    /// Generate a `Session` from a request and its metadata.
    ///
    /// # Errors
    ///
    /// * `SessionError::SessionCreateError` - if a session can't be created.
    pub fn new_from_request(request: &Request) -> Result<Self, SessionError> {
        let user_agent_header = request
            .headers()
            .get(axum::http::header::USER_AGENT)
            .cloned();
        let user_agent = if let Some(user_agent) = user_agent_header {
            user_agent.to_str().ok().map(ToString::to_string)
        } else {
            None
        };

        let client_ip = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .copied()
            .map(|client_ip| client_ip.ip());

        let start = chrono::Utc::now();
        let Some(expiry) = start.checked_add_days(chrono::Days::new(1)) else {
            // Absurd, but technically possible
            return Err(SessionError::SessionCreationError(
                "couldn't set expiry time".into(),
            ));
        };

        Ok(Session {
            uuid: Uuid::new_v4(),
            user_id: None,
            started_at: start,
            expires_at: expiry,
            revoked_at: None,
            revoked_by_user_id: None,
            fingerprint: SessionFingerprint {
                user_agent,
                ip_address: client_ip,
            },
            data: SessionDataStore::default(),
        })
    }

    /// Get the UUID for this session.
    #[must_use]
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

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
    sessions: HashMap<uuid::Uuid, Arc<Mutex<Session>>>,
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
        match self
            .sessions
            .try_insert(session.uuid, Arc::new(Mutex::new(session)))
        {
            Ok(_old_session_data) => Ok(()),
            Err(_e) => Err(SessionError::SessionAlreadyExists),
        }
    }

    /// Returns a mutable reference to a session if it exists.
    ///
    /// **IMPORTANT:** don't hold this lock while `await`ing the `Next` function in a middleware
    /// unless you're certain that inner calls won't use it. It's an easy way to cause deadlocks.
    ///
    /// Usually you can just use an `Extension` extractor to get access to this, and you won't need
    /// to call this function directly. You might use this e.g. to implement an admin user
    /// manipulating a session on behalf of another user, or when some user wants to invalidate a
    /// session from another browser/client.
    #[must_use]
    pub fn get_session_handle(&self, uuid: &Uuid) -> Option<Arc<Mutex<Session>>> {
        self.sessions.get(uuid).cloned()
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
