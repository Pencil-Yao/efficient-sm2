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

use crate::elem::Scalar;
use crate::err::KeyRejectedError;
use crate::limb::{LIMB_BYTES, LIMB_LENGTH};
use crate::norop::{norop_limbs_less_than, parse_big_endian};
use crate::rand::SecureRandom;
use crate::sm2p256::CURVE_PARAMS;
use core::marker::PhantomData;
use rand::Rng;

pub(crate) fn create_private_key(rng: &mut dyn SecureRandom) -> Result<Scalar, KeyRejectedError> {
    let mut seed = [0; LIMB_LENGTH * LIMB_BYTES];
    let mut candidate = [0; LIMB_LENGTH];

    // XXX: The value 100 was chosen to match OpenSSL due to uncertainty of
    // what specific value would be better, but it seems bad to try 100 times.
    for _ in 0..100 {
        rng.fill(&mut seed);
        parse_big_endian(&mut candidate, &seed)?;

        if norop_limbs_less_than(&candidate, &CURVE_PARAMS.n) {
            return Ok(Scalar {
                limbs: candidate,
                m: PhantomData,
            });
        }
    }

    Err(KeyRejectedError::SeedOperationFailed)
}

pub fn create_key_slice() -> [u8; LIMB_BYTES * LIMB_LENGTH] {
    let mut out = [0; LIMB_LENGTH * LIMB_BYTES];
    let mut candidate = [0; LIMB_LENGTH];

    for _ in 0..100 {
        let mut rng = rand::thread_rng();
        rng.fill(&mut out);
        parse_big_endian(&mut candidate, &out).unwrap();

        if norop_limbs_less_than(&candidate, &CURVE_PARAMS.n) {
            break;
        }
    }

    out
}
