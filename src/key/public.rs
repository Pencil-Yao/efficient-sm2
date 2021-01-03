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

use crate::elem::{scalar_to_unencoded, Scalar, R};
use crate::err::KeyRejected;
use crate::jacobian::exchange::big_endian_affine_from_jacobian;
use crate::limb::{Limb, LIMB_BYTES, LIMB_LENGTH};
use crate::norop::parse_big_endian;
use crate::sm2p256::{base_point_mul, to_jacobi, to_mont};

#[derive(Copy, Clone)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_LEN],
}

impl PublicKey {
    pub fn new(x: &[u8; LIMB_LENGTH * LIMB_BYTES], y: &[u8; LIMB_LENGTH * LIMB_BYTES]) -> Self {
        let mut public = PublicKey {
            bytes: [0; PUBLIC_KEY_LEN],
        };
        public.bytes[0] = 4;
        public.bytes[1..1 + LIMB_LENGTH * LIMB_BYTES].copy_from_slice(x);
        public.bytes[1 + LIMB_LENGTH * LIMB_BYTES..].copy_from_slice(y);

        public
    }

    pub fn bytes_less_safe(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_point(&self) -> [Limb; LIMB_LENGTH * 3] {
        let mut x = [0; LIMB_LENGTH];
        parse_big_endian(&mut x, &self.bytes[1..LIMB_LENGTH * LIMB_BYTES + 1]).unwrap();
        let x_aff = to_mont(&x);

        let mut y = [0; LIMB_LENGTH];
        parse_big_endian(&mut y, &self.bytes[LIMB_LENGTH * LIMB_BYTES + 1..]).unwrap();
        let y_aff = to_mont(&y);

        to_jacobi(&x_aff, &y_aff)
    }

    pub fn public_from_private(d: &Scalar<R>) -> Result<PublicKey, KeyRejected> {
        let du = scalar_to_unencoded(d);
        let pk_point = base_point_mul(&du.limbs);
        let mut x = [0; LIMB_LENGTH * LIMB_BYTES];
        let mut y = [0; LIMB_LENGTH * LIMB_BYTES];

        big_endian_affine_from_jacobian(&mut x, &mut y, &pk_point)?;

        Ok(PublicKey::new(&x, &y))
    }
}

pub const PUBLIC_KEY_LEN: usize = 1 + (2 * LIMB_LENGTH * LIMB_BYTES);
