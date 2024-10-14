//! `anodyne` is an opinionated set of utilities for building web applications (mostly with `axum`).

/// Types associated with anodyne.
pub mod types {
    /// Represents the input type of a form field.
    #[derive(Default, Debug)]
    pub enum FormFieldInputType {
        #[default]
        Text,
        Password,
        Email,
        // TODO...
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
}

pub mod traits {
    use std::collections::HashMap;

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
        /// Returns `Ok(())` or a hashmap of input name to `Vec` of error messages for validation
        /// failures.
        fn validate(&self) -> Result<(), HashMap<&'static str, Vec<&'static str>>>;
    }
}

pub mod exports {
    pub use regex;
}

// TODO: feature 'macros'
pub mod derive {
    pub use anodyne_derive::Form;
}

// TODO: macro testing
