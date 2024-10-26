use std::collections::HashMap;

use crate::types::{FormBuilder, FormFieldConfig};

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
#[crate::typetag::serde(tag = "type")]
pub trait Form: std::fmt::Debug {
    /// Returns `Ok(())` or a hashmap of input name to `Vec` of error messages for validation
    /// failures.
    ///
    /// # Errors
    ///
    /// * If form fails validation then it will return a `HashMap` of `field name` to `Vec<&str>`
    ///   describing the errors for that field.
    fn validate(&self) -> Result<(), HashMap<&'static str, Vec<&'static str>>>;

    /// Get a list of configuration info for each field (in the order fields appear in the struct
    /// from which the `Form` trait is derived)
    fn field_configs(&self) -> &'static [FormFieldConfig];

    /// Generate a form partial with fields representing the struct from which the `Form` trait is
    /// derived.
    fn form_partial<'a>(
        &self,
        method: &'a axum::http::Method,
        action: &'a str,
        errors: HashMap<&'static str, Vec<&'static str>>,
    ) -> FormBuilder<'a> {
        FormBuilder {
            configs: self
                .field_configs()
                .iter()
                .zip(self.prefill_values())
                .collect::<Vec<_>>(),
            errors,
            method,
            action,
        }
    }

    // TODO: this should be a map so that you can see how it works just by looking at a debug print.
    /// This returns values to refill after validation errors occur. Convention: values are in the
    /// same order they appear in the form.
    fn prefill_values(&self) -> Vec<Option<String>>;
}
