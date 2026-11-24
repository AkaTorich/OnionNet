//! UI text.
//!
//! Every phrase a person reads lives in one table, `strings_en.rs`. Code and
//! markup carry a key, never a sentence, so the wording is changed in one
//! place.
//!
//! Exception messages are deliberately NOT here. They are read by whoever
//! keeps the code, not by whoever runs it, and they stay in place.

pub mod loc;
pub mod strings_en;

pub use loc::{t, t_args};
