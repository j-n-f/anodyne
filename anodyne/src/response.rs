use std::sync::Arc;

use axum::{body::Body, http::Response, response::Redirect};

/// Expected return type for handler functions
pub type AnodyneResult<TForm> = Result<AnodyneResponse<TForm>, AnodyneError>;

/// A non-error response from a handler.
#[derive(Default)]
pub struct AnodyneResponse<T> {
    // TODO: members shouldn't be pub, but I'm not sure what I want the API to look like yet

    // TODO: `target_method` and `target_route` should be members of the response types for which
    //       they apply (see `AnodyneResponseContent`)
    /// HTTP method for certain types of responses.
    pub target_method: Option<axum::http::Method>,
    /// route for certain types of responses.
    pub target_route: Option<String>,
    /// Details for specific kind of response.
    pub content: AnodyneResponseContent<T>,
}

/// Content of a successful, non-error response.
#[derive(Default)]
pub enum AnodyneResponseContent<T> {
    /// Data response (may be turned into a partial or JSON, etc.).
    Data(T),
    /// Redirects the user to go somewhere else.
    Redirect(String),
    /// Empty response that isn't any of the other types.
    #[default]
    Empty,
}

impl<T> AnodyneResponse<T>
where
    T: crate::traits::Form + Default,
{
    /// Build a response with the given data.
    #[must_use]
    pub fn from_data(data: T) -> Self {
        Self {
            content: AnodyneResponseContent::Data(data),
            ..Default::default()
        }
    }

    /// Specify that a generated form partial should have its method set to POST.
    #[must_use]
    pub fn as_post(self) -> Self {
        Self {
            target_method: Some(axum::http::Method::POST),
            ..self
        }
    }

    // TODO: `ToString` should probably be `ToRoute` so we can constrain what gets passed to this
    //       function.
    /// Specify the target route for a form partial.
    #[must_use]
    pub fn with_route<R: ToString + ?Sized>(self, route: &R) -> Self {
        Self {
            target_route: Some(route.to_string()),
            ..self
        }
    }
}

/// Data passed from a handler into rendering middleware.
#[derive(Clone)]
pub(crate) struct LazyViewData<'a> {
    /// Form data (could be refill data, default values from handler, or just normal data for a
    /// view).
    pub data: Arc<dyn crate::traits::Form + Send + Sync + 'a>,
    /// Method for a form partial (if that's what's being rendered).
    pub form_method: Option<axum::http::Method>,
    /// Target URL for a form partial (if that's what's being rendered).
    pub form_url: Option<String>,
}

impl<T> axum::response::IntoResponse for AnodyneResponse<T>
where
    T: crate::traits::Form + Send + Sync + 'static + std::fmt::Debug + Default,
{
    fn into_response(self) -> axum::response::Response {
        // TODO: instead of using this empty response + extension trick, it may be possible to
        //       provide an implementation of the Body trait instead.
        let mut response = Response::new(Body::empty());

        let ext = response.extensions_mut();

        let AnodyneResponse {
            content,
            target_method,
            target_route,
        } = self;

        match content {
            AnodyneResponseContent::Data(data) => {
                // TODO: trace logs
                //println!("adding extension for AnodyneResponse");
                //println!("data: {data:#?}");
                let insertion = ext.insert(LazyViewData {
                    data: Arc::new(data),
                    form_method: target_method,
                    form_url: target_route,
                });

                assert!(insertion.is_none(), "response already had lazy view data");
            }
            AnodyneResponseContent::Redirect(url) => {
                response = Redirect::to(&url).into_response();
            }
            AnodyneResponseContent::Empty => {}
        }

        response
    }
}

// TODO: work out variants for this
/// Errors that can be returned by handlers.
pub enum AnodyneError {}

impl axum::response::IntoResponse for AnodyneError {
    fn into_response(self) -> axum::response::Response {
        // TODO: figure out how to convert errors to user-visible views
        Response::default()
    }
}
