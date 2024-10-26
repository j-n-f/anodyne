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
    #[must_use]
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
    #[must_use]
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

pub use fool_clippy::FormBuilder;

mod fool_clippy {
    // Annoying, but this is how it has to be
    // TODO: find a better solution
    #![allow(clippy::needless_lifetimes)]
    #![allow(clippy::must_use_candidate)]

    use std::collections::HashMap;

    use super::FormFieldConfig;

    markup::define! {
        FormBuilder<'a>(
            configs: Vec<(&'a FormFieldConfig, Option<String>)>,
            //prefill_values: HashMap<String, String>,
            errors: HashMap<&'static str, Vec<&'static str>>,
            method: &'a axum::http::Method,
            action: &'a str,
        ) {
            form [action=action, method={method.as_str()}] {
                @for (config, prefill) in configs.iter() {
                    label [for={config.input_name}] {
                        @config.label
                    }
                    div ."form-input" {
                        input [
                            name={config.input_name},
                            r#type={config.input_type.as_str()},
                            required={config.required},
                            value={prefill}
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
