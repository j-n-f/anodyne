# anodyne

An experimental framework for more easily building full-stack applications with
[`axum`](https://github.com/tokio-rs/axum).

## Motivation

While building applications with `axum` + HTMX, the same code was being written over and over again.
This framework is an attempt to reduce boilerplate by deriving it from structure definitions. This
is different from something like `loco` where you would use a CLI scaffolding tool to generate both
structures and code. With `anodyne` you start from data definitions and the code is generated for
you.

Many frameworks take a highly-modular approach which requires writing a lot of glue code, and makes
it more difficult to provide tight integration between concerns.

As an example: there are several excellent validation libraries for rust/axum, but this still
requires you to manually run validation in every single handler.

For a simple backend API this is fine, but for building full-stack applications it becomes tedious
and error-prone.

## Objectives

* Less boilerplate - common tasks (like building forms, validation, etc.) should be easy to
  implement allowing for easy scaffolding.
* Reliable - code generation reduces opportunity for errors.
* Flexible - easy scaffolding doesn't prevent customization when necessary.
* Performance - requests should be handled quickly and with low resource consumption.
* Batteries Included - everything needed is included by default and already integrated.
* Graceful Degradation - without extra effort on the developer's part applications should function
  even without client-side scripting enabled. (this is one of the most interesting possibilities
  for HTMX)
* Minimal Frontend - A single codebase for BE/FE means everything stays synchronized.

## Current Progress

Implementation is changing rapidly as details are worked out, but here's what's implemented so far:

* Session store - every user of the site gets a unique session ID, data can be associated with a
  session.
* Form builder with validation - easily specify the contents of a form along with validation rules.
  An extractor is provided which will automatically redirect to the original form if validation
  errors occur (i.e. you don't have to explicitly handle validation in your handler function)

As an example:

```rust
#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/my-form", get(show_form).post(handle_form))
        // layer in anodyne middlewares (these will eventually be merged into a single service)
        // TODO: update this once middleware has been finalized
        ;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4000").await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

#[derive(Deserialize, Serialize, Form, Default, Debug)]
pub struct MyForm {
    // HTML input name will be `exact_length`, but label will be as specified in attribute
    #[form(
        label="Enter eight characters"
        // Validation will ensure length of value is exactly 8 characters
        len=8,
        // Validation will ensure input matches this regex
        regex="^[A-Za-z0-9]+$",
        // Validation will show this error if regex doesn't match
        regex_description="must be only alphanumeric characters"
    )]
    exact_length: String
    #[form(
        // You can also use range specifiers for length validation
        len=8..=32
    )]
    password: String,
    #[form(
        // You can reference a field in this struct which this field must match
        matches=password
        // The label for this field will be "Confirm Password" (automatically converted from
        // snake-case)
    )]
    confirm_password: String,
}

async fn show_form() -> AnodyneResult<MyForm> {
    Ok(
        AnodyneResponse::from_data(
            // Here we specify that the form is initialized as empty, but you could provide some
            // pre-filled values if you wanted by passing a filled-in struct.
            MyForm::default()
        )
            .as_post() // Method for this form will be POST
            .with_route("/my-form") // Where data will be posted
    )
}

// This function could return AnodyneResult, or you can freely mix/match axum responses
async fn handle_form(FormData(form): FormData<MyForm>) -> impl IntoResponse {
    // You can access data in `form` and it's already valid by this point. If the user caused
    // a validation error they've already been redirected to the form to correct those errors.
}
```

## Future Considerations

* Extended form builder functionality - e.g. specify autocomplete logic for a field, or more complex
  data types like a list of ids for tags, datepickers, etc.
* Integrate model validation into the existing validation logic (e.g. ensure a value for some field
  is unique in the target table).
* Model support - Similar to the form builder, it should be possible to specify models as data
  structures and derive an implementation for the query builder (something similar to LINQ/EF from
  .NET would be cool).
* Extensions for various backends (db with connection pool, queues, storage, etc.).
* User/Role management and permissions.
* Observability.
* HTMX integration (other frameworks can be supported, but HTMX is really well suited to the
  intent of this framework).
* Model seeding - generate common types of data easily so that developers can get a sense of what
  their application looks like and how it behaves as it scales.
* REPL-like functionality for interacting with models, similar to rails/laravel console. While rust
  doesn't lend itself to a fully interactive REPL, the ability to easily manipulate models is useful
  for development. You can manually create records in a database, but this doesn't exercise model
  functionality.
* Transparent support for switching between rendered views and API responses. Handlers in anodyne
  return structured data, and so it becomes easier to switch view formats based on something like
  the `Accept` header sent in a request.
