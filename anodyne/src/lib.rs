//! `anodyne` is an opinionated set of utilities for building web applications (mostly with `axum`).

#[doc(inline)]
pub use router::AnodyneRouter as Router;
pub use serde;

//pub fn serve(listener: tokio::net::tcp::listener::TcpListener, )

pub mod router {}

pub mod extract {
    // TODO: consider renaming this to avoid colliding with names in Axum
    pub struct Form<T>(pub T);
}

/// Types associated with anodyne.
pub mod types {
    use std::collections::{hash_map::Entry, HashMap};

    /// Represents the input type of a form field.
    #[derive(Default, Debug)]
    pub enum FormFieldInputType {
        #[default]
        Text,
        Password,
        Email,
        // TODO...
    }

    impl FormFieldInputType {
        pub const fn as_str(&self) -> &'static str {
            match self {
                FormFieldInputType::Text => "text",
                FormFieldInputType::Password => "password",
                FormFieldInputType::Email => "email",
            }
        }
    }

    /// Used to build forms.
    #[derive(Debug)]
    pub struct FormFieldConfig {
        /// as in `<input name="...">`
        #[allow(unused)] // TODO
        input_name: &'static str,
        /// Defaults to a capitalized version of `FormFieldConfig::name` (with underscores turned
        /// into spaces). Can be modified with `#[field(label = "My Custom Label")]`.
        #[allow(unused)] // TODO
        label: &'static str,
        #[allow(unused)] // TODO
        input_type: FormFieldInputType,
        #[allow(unused)] // TODO
        required: bool,
    }

    impl FormFieldConfig {
        pub const fn new(
            input_name: &'static str,
            label: &'static str,
            input_type: FormFieldInputType,
            required: bool,
        ) -> Self {
            Self {
                input_name,
                label,
                input_type,
                required,
            }
        }
    }

    markup::define! {
        FormBuilder<'a>(
            configs: &'a [FormFieldConfig],
            errors: HashMap<&'static str, Vec<&'static str>>,
            method: axum::http::Method,
            action: &'a str,
        ) {
            form [action=action, method={method.as_str()}] {
                @for config in configs.iter() {
                    label [for={config.input_name}] {
                        @config.label
                    }
                    div ."form-input" {
                        input [
                            name={config.input_name},
                            r#type={config.input_type.as_str()},
                            required={config.required},
                            value="some value"
                        ] {}
                        @if let Some(error_list) = errors.get(config.input_name) {
                            div ."form-input-errors" {
                                ul {
                                    @for error in error_list.iter() {
                                        li {
                                            @error
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                input [r#type="submit"] {}
            }
        }
    }
}

pub mod traits {
    use std::{collections::HashMap, convert::Infallible};

    /// Allows building and validating forms.
    ///
    /// Typically implemented with `#[derive(Form)]`.
    ///
    /// An example:
    ///
    /// ```rust
    /// use anodyne::derive::Form;
    ///
    /// #[derive(Form)]
    /// pub struct LoginForm {
    ///     #[form(
    ///         // Use range syntax to control allowable lengths
    ///         len=8..=64,
    ///         // Use regexes to constrain content
    ///         regex="^[A-Za-z0-9_-]+$",
    ///         // Provide a less nerdy error message
    ///         regex_description="must contain only alphanumeric characters and underscore/hyphen",
    ///     )]
    ///     username: String,
    ///     // Ensure fields match, override automatic label generation
    ///     #[form(len=8..=64, matches=username, label="Confirm Your Username")]
    ///     confirm_username: String,
    ///     #[form(
    ///         // Renames the field when rendered to view
    ///         name="renamed_password",
    ///         // Override field type (defaults to "text")
    ///         input_type="password", // TODO: document use of `FormFieldInputType`
    ///     )]
    ///     password: String,
    /// }
    /// ```
    pub trait Form {
        // TODO: serde::Deserialize as a supertrait?
        // (without this you get hard to parse errors on handler functions when you use a struct
        // that doesn't implement `Deserialize` as an extractor)

        /// Returns `Ok(())` or a hashmap of input name to `Vec` of error messages for validation
        /// failures.
        fn validate(&self) -> Result<(), HashMap<&'static str, Vec<&'static str>>>;

        fn field_configs(&self) -> &'static [FormFieldConfig]; // TODO: derive

        // TODO: zip(config, values), errors
        fn form_partial<'a>(
            &'a self,
            method: axum::http::Method,
            action: &'a str,
        ) -> FormBuilder<'a> {
            FormBuilder {
                configs: self.field_configs(),
                errors: HashMap::new(),
                method,
                action,
            }
        }
    }

    use axum::{response::IntoResponse, RequestExt};

    use crate::types::{FormBuilder, FormFieldConfig};

    /// This can be used to fetch extra fields that are common to all forms.
    #[derive(serde::Deserialize, Debug)]
    struct FormCommon {
        // as an example
        __csrf_token: Option<String>,
        // e.g. for supporting PATCH, DELETE, etc. when HTML forms don't
        __patched_method: Option<String>,
    }

    #[axum::async_trait]
    impl<T, S> ::axum::extract::FromRequest<S> for crate::extract::Form<T>
    where
        T: ::serde::de::DeserializeOwned + Form,
        S: Send + Sync,
    {
        // We always have a way to handle errors when performing form handling.
        //type Rejection = Infallible;
        type Rejection = ();

        // I think it's infallible, double-check that...

        async fn from_request(
            req: ::axum::extract::Request,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            // TODO: use this to redirect back to the form when errors are present
            let _referer = req.headers().get(axum::http::header::REFERER);

            // TODO: support other request types
            if req.method() != ::axum::http::Method::POST {
                return Err(());
            }

            // TODO: branch on content-accept: HTML, and JSON (API for free, without special route)

            // BEFORECOMMIT: redirect to referer on error (don't worry about success, controller
            //               will handle that).

            match req.extract().await {
                Ok(::axum::extract::RawForm(bytes)) => {
                    // TODO: how to get out extra fields, like csrf tokens, etc?
                    let value: T = ::serde_urlencoded::from_bytes(&bytes)
                        .map_err(|err| -> Self::Rejection { () })?;
                    let extra: FormCommon = ::serde_urlencoded::from_bytes(&bytes)
                        .map_err(|err| -> Self::Rejection { () })?;

                    println!("validation result = {:#?}", value.validate());
                    println!("extra = {:#?}", extra);

                    match value.validate() {
                        Ok(()) => {
                            println!("form validated");
                            todo!()
                        }
                        Err(map) => {
                            println!("form error; redirect");
                            todo!()
                        }
                    }
                }
                _ => return Err(()),
            }

            // we get a POST
            // all the fields validate
            //      TODO: somehow also perform model validation
            // clear any records from the session store (maybe this actually has to happen in
            // middleware after success)
            // #struct_ident gets passed to the handler

            // we get a POST
            // some struct fields fail to validate
            // we stick any "refill=true" fields into S::session_store
            // we redirect to the place the form was submitted from (how do we know this?)
            // it picks up when the user ends up at that page, it sticks in the session
            //   until it succeeds or some expiry timer is met

            // TODO: handle GET (use case for this is not yet clear)
        }
    }

    //impl IntoResponse for Form<T> {
    //    fn into_response(self) -> axum::response::Response {
    //        // How TF do I get the request parameters here?
    //        todo!()
    //    }
    //}

    // TODO: implement Body so that you can use a custom body return type :D
}

pub mod exports {
    pub use regex;
}

// TODO: feature 'macros'
pub mod derive {
    pub use anodyne_derive::Form;
}

// TODO: macro testing
