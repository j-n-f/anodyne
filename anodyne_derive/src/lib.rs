//! Derive macros for use with `anodyne`.

#![deny(clippy::all)]
#![warn(clippy::pedantic)]
// TODO: unless these become available in +stable soon then anything depending on these will need to
//       get backported somehow.
#![feature(new_range_api)]
#![feature(slice_range)]
#![feature(debug_closure_helpers)]
#![feature(extend_one)]

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod implementation;

#[proc_macro_derive(Form, attributes(form))]
pub fn derive_validates(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    implementation::derive_validates_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
