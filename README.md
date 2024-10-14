# anodyne

An opinionated set of tools for building applications (mostly with
[`axum`](https://github.com/tokio-rs/axum)).

Crate will change often and without warning until `1.0.0`.

## work in progress

* [ ] `trait Form` should generate form partials
    * [ ] [`markup.rs`](https://github.com/utkarshkukreti/markup.rs)
* [ ] `trait Form` should generate an htmx-aware extractor which can automatically redirect to the
      form when validation errors occur (will need some form of session storage for this).
* [ ] macro testing for `Form`
