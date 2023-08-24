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

use crate::elem::{
    elem_mul, elem_reduced_to_scalar, elem_to_unencoded, point_x, point_z, scalar_add, scalar_sub,
    scalar_to_elem, twin_mul, Elem, Scalar, Unencoded,
};
use crate::err::KeyRejectedError;
use crate::jacobian::exchange::verify_jacobian_point_is_on_the_curve;
use crate::key::public::PublicKey;
use crate::limb::{Limb, LIMB_BYTES, LIMB_LENGTH};
use crate::norop::{big_endian_from_limbs, parse_big_endian};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Signature {
    r: Scalar,
    s: Scalar,
}

impl Signature {
    pub fn new(r: &[u8], s: &[u8]) -> Result<Self, KeyRejectedError> {
        let mut rl = [0; LIMB_LENGTH];
        parse_big_endian(&mut rl, r)?;
        let r = Scalar {
            limbs: rl,
            m: PhantomData,
        };

        let mut sl = [0; LIMB_LENGTH];
        parse_big_endian(&mut sl, s)?;
        let s = Scalar {
            limbs: sl,
            m: PhantomData,
        };

        Ok(Signature { r, s })
    }

    pub fn from_slice(sig: &[u8]) -> Result<Self, KeyRejectedError> {
        Self::new(
            &sig[..LIMB_LENGTH * LIMB_BYTES],
            &sig[LIMB_LENGTH * LIMB_BYTES..],
        )
    }

    pub fn from_scalars(r: Scalar, s: Scalar) -> Self {
        Signature { r, s }
    }

    pub fn r(&self) -> [u8; LIMB_LENGTH * LIMB_BYTES] {
        let mut r_out = [0; LIMB_LENGTH * LIMB_BYTES];
        big_endian_from_limbs(&self.r.limbs, &mut r_out);
        r_out
    }

    pub fn s(&self) -> [u8; LIMB_LENGTH * LIMB_BYTES] {
        let mut s_out = [0; LIMB_LENGTH * LIMB_BYTES];
        big_endian_from_limbs(&self.s.limbs, &mut s_out);
        s_out
    }

    pub fn verify(&self, pk: &PublicKey, msg: &[u8]) -> Result<(), KeyRejectedError> {
        let ctx = libsm::sm2::signature::SigCtx::new();
        let pk_point = ctx
            .load_pubkey(pk.bytes_less_safe())
            .map_err(|e| KeyRejectedError::LibSmError(format!("{e}")))?;
        let digest = ctx
            .hash("1234567812345678", &pk_point, msg)
            .map_err(|e| KeyRejectedError::LibSmError(format!("{e}")))?;

        self.verify_digest(pk, &digest)
    }

    pub fn verify_digest(&self, pk: &PublicKey, digest: &[u8]) -> Result<(), KeyRejectedError> {
        let mut dl = [0; LIMB_LENGTH];
        parse_big_endian(&mut dl, digest)?;
        let edl = Elem {
            limbs: dl,
            m: PhantomData,
        };
        let e = elem_reduced_to_scalar(&edl);

        let (u1, u2) = (&self.s, scalar_add(&self.r, &self.s));
        let r = scalar_sub(&self.r, &e);

        let point = twin_mul(u1, &u2, pk);

        verify_jacobian_point_is_on_the_curve(&point)?;

        fn sig_r_equals_x(r: &Elem<Unencoded>, point: &[Limb; LIMB_LENGTH * 3]) -> bool {
            let x = point_x(point);
            let z = point_z(point);
            let z2 = elem_mul(&z, &z);
            let r_jacobian = elem_mul(&z2, r);
            let x = elem_to_unencoded(&x);
            r_jacobian.is_equal(&x)
        }

        let r = scalar_to_elem(&r);
        if sig_r_equals_x(&r, &point) {
            return Ok(());
        }
        Err(KeyRejectedError::VerifyDigestFailed)
    }
}
