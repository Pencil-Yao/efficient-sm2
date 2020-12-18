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

use crate::ec::verification::Signature;
use crate::elem::{
    elem_reduced_to_scalar, elem_to_unencoded, scalar_add, scalar_inv_to_mont, scalar_mul,
    scalar_sub, scalar_to_unencoded, Elem, Scalar, R,
};
use crate::err::KeyRejected;
use crate::jacobian::exchange::{affine_from_jacobian, big_endian_affine_from_jacobian};
use crate::key::private::create_private_key;
use crate::key::public::PublicKey;
use crate::limb::{LIMB_BYTES, LIMB_LENGTH, ONE};
use crate::norop::parse_big_endian;
use crate::rand::SecureRandom;
use crate::sm2p256::{base_point_mul, scalar_to_mont};
use core::marker::PhantomData;

pub struct KeyPair {
    d: Scalar<R>, // *R*
}

impl KeyPair {
    pub fn new(private_key: &[u8; LIMB_LENGTH * LIMB_BYTES]) -> Result<Self, KeyRejected> {
        let mut key_limb = [0; LIMB_LENGTH];
        parse_big_endian(&mut key_limb, private_key)?;
        let d = Scalar {
            limbs: scalar_to_mont(&key_limb),
            m: PhantomData,
        };
        Ok(KeyPair { d })
    }

    pub fn public_from_private(&self) -> Result<PublicKey, KeyRejected> {
        let du = scalar_to_unencoded(&self.d);
        let pk_point = base_point_mul(&du.limbs);
        let mut x = [0; LIMB_LENGTH * LIMB_BYTES];
        let mut y = [0; LIMB_LENGTH * LIMB_BYTES];

        big_endian_affine_from_jacobian(&mut x, &mut y, &pk_point)?;

        Ok(PublicKey::new(&x, &y))
    }

    pub fn sign(
        &self,
        rng: &mut dyn SecureRandom,
        message: &[u8],
    ) -> Result<Signature, KeyRejected> {
        let ctx = libsm::sm2::signature::SigCtx::new();
        let pk_point = ctx
            .load_pubkey(self.public_from_private().unwrap().bytes_less_safe())
            .map_err(|_| KeyRejected::sign_error())?;
        let digest = ctx.hash("1234567812345678", &pk_point, message);

        self.sign_digest(rng, &digest)
    }

    fn sign_digest(
        &self,
        rng: &mut dyn SecureRandom,
        digest: &[u8],
    ) -> Result<Signature, KeyRejected> {
        for _ in 0..100 {
            let rk = create_private_key(rng)?;

            let rq = base_point_mul(&rk.limbs);

            let r = {
                let (x, _) = affine_from_jacobian(&rq)?;
                let x = elem_to_unencoded(&x);
                elem_reduced_to_scalar(&x)
            };
            if r.is_zero() {
                continue;
            }

            let mut dl = [0; LIMB_LENGTH];
            parse_big_endian(&mut dl, digest)?;
            let edl = Elem {
                limbs: dl,
                m: PhantomData,
            };
            let e = elem_reduced_to_scalar(&edl);

            static SCALAR_ONE: Scalar = Scalar {
                limbs: ONE,
                m: PhantomData,
            };

            let r = scalar_add(&r, &e);

            let da_ue = scalar_to_unencoded(&self.d);
            let left = scalar_inv_to_mont(&scalar_add(&da_ue, &SCALAR_ONE));
            let dr = scalar_mul(&self.d, &r);
            let right = scalar_sub(&rk, &dr);
            let s = scalar_mul(&left, &right);

            return Ok(Signature::from_scalars(r, s));
        }
        Err(KeyRejected::sign_digest_error())
    }
}

#[cfg(test)]
mod tests {
    use rand::prelude::ThreadRng;
    use rand::Rng;
    use super::*;

    #[test]
    fn sign_verify_test() {
        pub struct EgRand(ThreadRng);

        impl SecureRandom for EgRand {
            fn fill(&mut self, dest: &mut [u8]) {
                self.0.fill(dest)
            }
        }

        let test_word = b"hello world";
        let mut rng = EgRand(rand::thread_rng());

        let mut private_key = [0; LIMB_LENGTH * LIMB_BYTES];
        rng.fill(&mut private_key);

        let key_pair = KeyPair::new(&private_key).unwrap();

        let sig = key_pair.sign(&mut rng, test_word).unwrap();

        let r = sig.r();
        let s = sig.s();
        let sig2 = Signature::new(&r, &s).unwrap();

        sig2.verify(&key_pair.public_from_private().unwrap(), test_word)
            .unwrap()
    }
}
