// Copyright 2016 Brian Smith.
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

//! Error reporting.

/// An error parsing or validating a key.
///
/// The `Display` implementation and `<KeyRejectedError as Error>::description()`
/// will return a string that will help you better understand why a key was
/// rejected change which errors are reported in which situations while
/// minimizing the likelihood that any applications will be broken.
///
/// Here is an incomplete list of reasons a key may be unsupported:
///
/// * Invalid or Inconsistent Components: A component of the key has an invalid
///   value, or the mathematical relationship between two (or more) components
///   required for a valid key does not hold.
///
/// * The encoding of the key is invalid. Perhaps the key isn't in the correct
///   format; e.g. it may be Base64 ("PEM") encoded, in which case   the Base64
///   encoding needs to be undone first.
///
/// * The encoding includes a versioning mechanism and that mechanism indicates
///   that the key is encoded in a version of the encoding that isn't supported.
///   This might happen for multi-prime RSA keys (keys with more than two
///   private   prime factors), which aren't supported, for example.
///
/// * Too small or too Large: One of the primary components of the key is too
///   small or two large. Too-small keys are rejected for security reasons. Some
///   unnecessarily large keys are rejected for performance reasons.
///
///  * Wrong algorithm: The key is not valid for the algorithm in which it was
///    being used.
///
///  * Unexpected errors: Report this as a bug.

#[derive(PartialEq, Clone, Debug)]
pub enum KeyRejectedError {
    SeedOperationFailed,
    SignDigestFailed,
    VerifyDigestFailed,
    ZeroError,
    NotOnCurveError,
    LibSmError(String),
    UnexpectedError,
}
