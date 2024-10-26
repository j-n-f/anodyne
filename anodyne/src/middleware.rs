use std::{collections::HashMap, sync::Arc};

use axum::{
    middleware::Next,
    response::{Html, IntoResponse, Response},
    Extension,
};
use tokio::sync::Mutex;

use crate::{
    response::LazyViewData,
    session::{SessionTable, SessionUuid},
    traits::Form,
};

type PrefillInfo = (
    Option<Box<dyn Form>>,
    HashMap<&'static str, Vec<&'static str>>,
);

/// Middleware to perform late-rendering of a view (once common framework data/state are resolved).
pub async fn lazy_render(
    // TODO: I would like it more if a single extension just gave me access to a Mutex for the
    //       pertinent session.
    Extension(session_table): Extension<Arc<Mutex<SessionTable>>>,
    Extension(session_info): Extension<SessionUuid>,
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

    match method {
        axum::http::Method::GET => {
            if let Some(LazyViewData {
                data: handler_form_data,
                form_method,
                form_url,
            }) = handler_response.extensions_mut().remove::<LazyViewData>()
            {
                let mut session_lock = session_table.lock().await;
                let session = session_lock.session_mut(&session_info.0);

                let prefill_resolved: Option<PrefillInfo> = match session {
                    Some(session) => {
                        // TODO: figure out a way around these pointless clones
                        let prefill_data =
                            session.data.route_data(&(method.clone(), route.clone()));

                        if let Some(prefill_data) = prefill_data {
                            // TODO: trace logs
                            let errors = prefill_data.1.clone();
                            let prefill_data: Option<Box<dyn Form>> =
                                serde_json::from_str(&prefill_data.0).ok();

                            Some((prefill_data, errors))
                        } else {
                            None
                        }
                    }
                    None => None,
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
