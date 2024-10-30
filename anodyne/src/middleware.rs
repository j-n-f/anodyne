use std::{collections::HashMap, sync::Arc};

use axum::{
    http::HeaderValue,
    middleware::Next,
    response::{Html, IntoResponse, Response},
    Extension,
};
use tokio::sync::{Mutex, RwLock};

use crate::{
    response::LazyViewData,
    session::{Session, SessionTable},
    traits::Form,
    util::{server_error, CookieJar},
};

type PrefillInfo = (
    Option<Box<dyn Form>>,
    HashMap<&'static str, Vec<&'static str>>,
);

// 1. Check headers and add Extension<SessionUuid>, branch if not exist and create
// 2. Check Extension<SessionUuid> and add Extension<SessionHandle>
// 3. Perform lazy rendering

// TODO: make Mutex per-session

pub type SessionTableExtension = Arc<RwLock<SessionTable>>;

/// Ensures that a session exists for this request. It will be attached to the request as an
/// Extension (whether pre-existing or created on this request).
pub async fn ensure_session_middleware(
    Extension(session_table): Extension<SessionTableExtension>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let Ok(cookie_jar) = CookieJar::from_request(&request) else {
        // Return early if we can't fetch cookies
        return (axum::http::StatusCode::BAD_REQUEST, "cookie failure").into_response();
    };

    let encoded_session_cookie = cookie_jar.get_cookie_named("session");

    let mut current_session = None;

    let mut found_session = false;
    if let Some(base64) = encoded_session_cookie {
        if let Ok(uuid) = SessionTable::get_session_uuid_from_cookie(base64) {
            let session_table_handle = session_table.read().await;
            if let Some(existing_session) = session_table_handle.get_session_handle(&uuid) {
                current_session = Some(existing_session);
                found_session = true;
            }
        }
    }

    // This will only be set if we generate a new cookie for a new session
    let mut new_cookie = None;
    if !found_session {
        let Ok(new_session) = Session::new_from_request(&request) else {
            return server_error!("bad request, can't create session");
        };

        let new_uuid = new_session.uuid();
        new_cookie = new_session.as_cookie().ok();
        let mut session_table_handle = session_table.write().await;
        if session_table_handle.insert_session(new_session).is_ok() {
            if let Some(session_mut) = session_table_handle.get_session_handle(&new_uuid) {
                current_session = Some(session_mut);
            } else {
                return server_error!("session extension error");
            }
        } else {
            return server_error!("failed to create session");
        }
    }

    // Whether existing or newly created, add session to extensions
    if let Some(session) = current_session {
        request.extensions_mut().insert(session.clone());
    }

    // Run inner
    let mut response = next.run(request).await;

    // If we have a new cookie to send, we'll set the header for the response
    if let Some(cookie) = new_cookie {
        if let Ok(cookie_header_value) =
            HeaderValue::from_str(&format!("session={cookie}; HttpOnly"))
        {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, cookie_header_value);
        } else {
            return server_error!("failed to send Set-Cookie header");
        }
    }

    response
}

/// Middleware to perform late-rendering of a view (once common framework data/state are resolved).
pub async fn lazy_render_middleware(
    Extension(session): Extension<Arc<Mutex<Session>>>,
    // TODO: extractor for route key
    request: axum::extract::Request,
    next: Next,
) -> Response {
    // Method of current request
    let method = request.method().clone();
    // Route for current request
    let route = request.uri().clone().to_string();

    // Run handler, and get data needed to generate a response
    let mut handler_response = next.run(request).await;

    let session = session.lock().await;

    match method {
        axum::http::Method::GET => {
            if let Some(LazyViewData {
                data: handler_form_data,
                form_method,
                form_url,
            }) = handler_response.extensions_mut().remove::<LazyViewData>()
            {
                let prefill_data = session.data.route_data(&(method.clone(), route.clone()));

                let prefill_resolved: Option<PrefillInfo> = if let Some(prefill_data) = prefill_data
                {
                    // TODO: trace logs
                    let errors = prefill_data.1.clone();
                    let prefill_data: Option<Box<dyn Form>> =
                        serde_json::from_str(&prefill_data.0).ok();

                    Some((prefill_data, errors))
                } else {
                    None
                };

                // TODO: we should return some kind of error here instead of returning `/unknown`
                let effective_target_url = form_url.as_deref().unwrap_or("/unknown");
                let form_method = form_method.clone().unwrap_or(axum::http::Method::POST);
                let partial = match prefill_resolved {
                    // Prefill data in session, with errors
                    Some((Some(boxed_prefill), errors)) => {
                        boxed_prefill.form_partial(&form_method, effective_target_url, errors)
                    }
                    // No prefill data in session, with errors
                    Some((None, errors)) => {
                        handler_form_data.form_partial(&form_method, effective_target_url, errors)
                    }
                    // Requesting form for first time, no prefill and no errors
                    None => handler_form_data.form_partial(
                        &form_method,
                        effective_target_url,
                        HashMap::default(),
                    ),
                };

                // Assume request `Accept` header is for HTML
                // TODO: handle other content types
                let html = Html(partial.to_string());

                return html.into_response();
            }
        }
        _ => {
            // I don't think this should ever come up, any other kind of request should redirect to
            // a GET regardless of success/failure
            eprintln!("unhandled http method {method} in lazy_render middleware");
        }
    }

    // Otherwise we have no magic to do (i.e. they may be just returning something IntoResponse)
    handler_response
}
