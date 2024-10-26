//! `anodyne` is an opinionated set of utilities for building web applications (mostly with `axum`).

#![feature(map_try_insert)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[doc(inline)]
pub use axum;
#[doc(inline)]
pub use serde;

pub mod config;
// TODO: feature 'macros'
pub mod derive;
pub mod exports;
pub mod extract;
pub mod middleware;
pub mod response;
pub mod session;
pub mod traits;
pub mod types;
pub mod util;

// Re-export typetag
pub use typetag;

// TODO: macro testing
