// Copyright 2020 Yao Pengfei.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#![deny(
unstable_features, // Used by `internal_benches`
unused_qualifications,
variant_size_differences,
)]
#![forbid(
anonymous_parameters,
trivial_casts,
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
unused_results,
// warnings
)]
// #![no_std]
#![cfg_attr(feature = "internal_benches", allow(unstable_features), feature(test))]

mod ec;
mod elem;
mod err;
mod jacobian;
mod key;
pub mod limb;
mod norop;
mod rand;
mod sm2p256;
mod sm2p256_table;

pub use crate::rand::SecureRandom;
pub use ec::KeyPair;
pub use ec::Signature;
pub use key::public::PublicKey;
