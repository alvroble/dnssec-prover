//! The DNS provides a single, global, hierarchical namespace with (when DNSSEC is used)
//! cryptographic guarantees on all of its data.
//!
//! This makes it incredibly powerful for resolving human-readable names into arbitrary, secured
//! data.
//!
//! Unlike TLS, this cryptographic security provides transferable proofs which can convince an
//! offline device, using simple cryptographic primitives and a single root trusted key, of the
//! validity of DNS data.
//!
//! This crate implements the creation and validation of such proofs, using the format from RFC
//! 9102 to create transferable proofs of DNS entries.
//!
//! It is no-std (but requires `alloc`) and seeks to have minimal dependencies and a reasonably
//! conservative MSRV policy, allowing it to be used in as many places as possible.
//!
//! Most of the crate's logic is feature-gated, and *all dependencies are optional*:
//!  * By default, the `validate` feature is set, using `ring` to validate DNSSEC signatures and
//!    proofs using the [`validation`] module.
//!  * The `std` feature enables the [`query`] module, allowing for the building of proofs by
//!    querying a recursive resolver over TCP.
//!  * The `tokio` feature further enables async versions of the [`query`] methods, doing the same
//!    querying async using `tokio`'s TCP streams.
//!  * Finally, the crate can be built as a binary using the `build_server` feature, responding to
//!    queries over HTTP GET calls to `/dnssecproof?d=domain.name.&t=RecordType` with DNSSEC
//!    proofs.
//!
//! Note that this library's MSRV is 1.64 for normal building, however builds fine on 1.63 (and
//! possibly earlier) when `RUSTC_BOOTSTRAP=1` is set, as it relies on the
//! `const_slice_from_raw_parts` feature.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

// const_slice_from_raw_parts was stabilized in 1.64, however we support building on 1.63 as well.
// Luckily, it seems to work fine in 1.63 with the feature flag (and RUSTC_BOOTSTRAP=1) enabled.
#![cfg_attr(rust_1_63, feature(const_slice_from_raw_parts))]

#![allow(clippy::new_without_default)] // why is this even a lint
#![allow(clippy::result_unit_err)] // Why in the hell is this a lint?
#![allow(clippy::get_first)] // Sometimes this improves readability
#![allow(clippy::needless_lifetimes)] // lifetimes improve readability
#![allow(clippy::needless_borrow)] // borrows indicate read-only/non-move
#![allow(clippy::too_many_arguments)] // sometimes we don't have an option
#![allow(clippy::identity_op)] // sometimes identities improve readability for repeated actions
#![allow(clippy::erasing_op)] // sometimes identities improve readability for repeated actions

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

/// The maximum number of requests we will make when building a proof or the maximum number of
/// [`rr::RRSig`] sets we'll validate records from when validating proofs.
// Note that this is duplicated exactly in src/http.rs
pub const MAX_PROOF_STEPS: usize = 20;

#[cfg(feature = "validation")]
mod base32;

#[cfg(all(feature = "validation", any(fuzzing, dnssec_validate_bench)))]
pub mod crypto;
#[cfg(all(feature = "validation", not(any(fuzzing, dnssec_validate_bench))))]
mod crypto;

pub mod rr;
pub mod ser;
pub mod query;

#[cfg(feature = "validation")]
pub mod validation;

#[cfg(all(feature = "std", feature = "validation", test))]
mod test;
