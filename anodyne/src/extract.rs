use std::sync::Arc;

use axum::{
    response::{IntoResponse, Redirect},
    Extension, RequestExt,
};
use tokio::sync::Mutex;

use crate::session::{SessionTable, SessionUuid};

/// A form extractor which drives anodyne's automatic form handling. This extractor implements
/// `axum::extract::FromRequest` meaning that it must be the last argument to your handler function.
///
/// The generic argument to this extractor is a type which implements `anodyne::traits::Form` (which
/// you will likely derive).
///
/// Any time a request submits form data to a handler using this extractor, it will automatically
/// validate the data against the metadata specified in the type used as a generic argument. If
/// validation errors occur then the handler using this extractor won't run, and instead the user
/// will be redirected to the original form where validation errors will be displayed.
///
/// **TODO:** mechanism for model validation
pub struct FormData<T>(pub T);

/// Common data that all forms submit to support framework functionality.
#[derive(serde::Deserialize, Debug)]
struct FormCommon {
    /// CSRF Token
    __csrf_token: Option<String>,
    // TODO: this value should be authenticated to prevent malicious users from abusing it.
    /// To support methods like PATCH, DELETE, etc.
    __patched_method: Option<String>,
}

#[axum::async_trait]
impl<T, S> ::axum::extract::FromRequest<S> for crate::extract::FormData<T>
where
    T: ::serde::de::DeserializeOwned + crate::traits::Form + Send,
    S: Send + Sync,
{
    type Rejection = FormValidationError;

    async fn from_request(
        mut request: ::axum::http::Request<axum::body::Body>,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let referer_header = request
            .headers()
            .get(axum::http::header::REFERER)
            .unwrap()
            .clone();
        let referer_route = referer_header.to_str().unwrap();

        let host_header = request
            .headers()
            .get(axum::http::header::HOST)
            .unwrap()
            .clone();
        let host = host_header.to_str().unwrap();

        // TODO: Make an extractor for this logic
        // This is ugly, but most likely to work. It will require more research to figure out e.g.
        // how to handle clients that don't included the REFERER header.
        let Some(app_referer_route) = referer_route.split(&host).last() else {
            return Err(FormValidationError::unrecoverable("unknown referer route"));
        };

        // TODO: support other request types
        if request.method() != ::axum::http::Method::POST {
            return Err(FormValidationError::unrecoverable("unsupported method"));
        }

        // TODO: branch on content-accept: HTML, and JSON (API for free, without special route)

        let Ok(Extension(session_table)) = request
            .extract_parts::<Extension<Arc<Mutex<SessionTable>>>>()
            .await
        else {
            return Err(FormValidationError::unrecoverable(
                "session management error",
            ));
        };

        let Some(current_session_uuid) = request.extensions().get::<SessionUuid>().cloned() else {
            return Err(FormValidationError::unrecoverable("session error"));
        };

        match request.extract().await {
            Ok(::axum::extract::RawForm(bytes)) => {
                // TODO: how to get out extra fields, like csrf tokens, etc?
                let value: T = ::serde_urlencoded::from_bytes(&bytes).map_err(|_err| {
                    eprintln!("unimplemented: form deserialization failed");
                    FormValidationError::unrecoverable("deserialization error (1)")
                })?;
                let _extra: FormCommon =
                    ::serde_urlencoded::from_bytes(&bytes).map_err(|_err| {
                        eprintln!("unimplemented: form common deserialization failed");
                        FormValidationError::unrecoverable("deserialization error (2)")
                    })?;

                match value.validate() {
                    Ok(()) => {
                        // Clear any existing prefill values in session
                        let mut table = session_table.lock().await;

                        // store existing values in session
                        let Some(session) = table.session_mut(&current_session_uuid.0) else {
                            eprintln!("needed to store refill data but session didn't exist");
                            return Err(FormValidationError::unrecoverable("session error"));
                        };

                        let Ok(()) = session
                            .data
                            .clear_data(&(axum::http::Method::GET, app_referer_route.to_string()))
                        else {
                            return Err(FormValidationError::unrecoverable("session state error"));
                        };

                        // Release lock on session table
                        drop(table);

                        // Pass form data to its handler.
                        return Ok(FormData(value));
                    }
                    Err(map) => {
                        // Store values submitted so far in session data
                        let mut table = session_table.lock().await;

                        // store existing values in session
                        let Some(session) = table.session_mut(&current_session_uuid.0) else {
                            eprintln!("needed to store refill data but session didn't exist");
                            return Err(FormValidationError::unrecoverable("session error"));
                        };

                        // TODO: try flatbuffers
                        let refill_values = serde_json::to_string(
                            &value as &dyn crate::traits::Form,
                        )
                        .map_err(|_err| {
                            eprintln!("unimplemented: failed to serialize refill data to string");
                            FormValidationError::unrecoverable("serialization error")
                        })?;

                        // TODO: figure out more systematic way to resolve method/route to redirect
                        //       to. For now we'll just assume GET = form, POST = submission
                        session
                            .data
                            .update_data(
                                (axum::http::Method::GET, app_referer_route.to_string()),
                                (refill_values, map),
                            )
                            .expect("couldn't store erroneous form data in session");

                        // Release lock on session table
                        drop(table);

                        // redirect to referer
                        return Err(FormValidationError::redirect(
                            axum::http::Method::GET,
                            referer_route.to_string(),
                        ));
                    }
                }
            }
            Err(err) => {
                eprintln!("unimplemented: extraction failure: {err}");
                return Err(FormValidationError::unrecoverable("extraction error"));
            }
        }
    }
}

pub enum FormValidationError {
    /// Redirect user back to the form to correct errors
    Redirect {
        method: axum::http::Method,
        url: String,
    },
    /// There is nothing the user can do to resolve this issue (i.e. bug in the application logic).
    /// `user_visible_error` will be shown to the user along with a 500 response.
    Unrecoverable { user_visible_error: String },
}

impl FormValidationError {
    /// Redirect on validation failure (usually back to the form the error came from).
    #[must_use]
    pub fn redirect(method: axum::http::Method, url: String) -> Self {
        Self::Redirect { method, url }
    }

    /// Handle an unrecoverable error (this will become a 500).
    #[must_use]
    pub fn unrecoverable<T: ToString + ?Sized>(user_visible_error: &T) -> Self {
        Self::Unrecoverable {
            user_visible_error: user_visible_error.to_string(),
        }
    }
}

impl IntoResponse for FormValidationError {
    fn into_response(self) -> axum::response::Response {
        match self {
            FormValidationError::Redirect { method, url } => match method {
                // HTTP 303
                axum::http::Method::GET => Redirect::to(&url).into_response(),
                // HTTP 307
                _ => Redirect::temporary(&url).into_response(),
            },
            // HTTP 500
            FormValidationError::Unrecoverable { user_visible_error } => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                user_visible_error,
            )
                .into_response(),
        }
    }
}
