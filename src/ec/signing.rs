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
use crate::err::KeyRejectedError;
use crate::jacobian::exchange::affine_from_jacobian;
use crate::key::private::create_private_key;
use crate::key::public::PublicKey;
use crate::limb::{LIMB_LENGTH, ONE};
use crate::norop::parse_big_endian;
use crate::rand::{DefaultRand, SecureRandom};
use crate::sm2p256::{base_point_mul, scalar_to_mont};
use core::marker::PhantomData;

#[derive(Clone)]
pub struct KeyPair {
    d: Scalar<R>, // *R*
    pk: PublicKey,
}

impl KeyPair {
    pub fn new(private_key: &[u8]) -> Result<Self, KeyRejectedError> {
        let mut key_limb = [0; LIMB_LENGTH];
        parse_big_endian(&mut key_limb, private_key)?;
        let d = Scalar {
            limbs: scalar_to_mont(&key_limb),
            m: PhantomData,
        };
        let pk = PublicKey::public_from_private(&d)?;
        Ok(KeyPair { d, pk })
    }

    pub fn public_key(&self) -> PublicKey {
        self.pk
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature, KeyRejectedError> {
        let ctx = libsm::sm2::signature::SigCtx::new();
        let pk_point = ctx
            .load_pubkey(self.pk.bytes_less_safe())
            .map_err(|e| KeyRejectedError::LibSmError(format!("{e}")))?;
        let digest = ctx
            .hash("1234567812345678", &pk_point, message)
            .map_err(|e| KeyRejectedError::LibSmError(format!("{e}")))?;

        self.sign_digest(&mut DefaultRand(rand::thread_rng()), &digest)
    }

    pub fn sign_with_seed(
        &self,
        rng: &mut dyn SecureRandom,
        message: &[u8],
    ) -> Result<Signature, KeyRejectedError> {
        let ctx = libsm::sm2::signature::SigCtx::new();
        let pk_point = ctx
            .load_pubkey(self.pk.bytes_less_safe())
            .map_err(|e| KeyRejectedError::LibSmError(format!("{e}")))?;
        let digest = ctx
            .hash("1234567812345678", &pk_point, message)
            .map_err(|e| KeyRejectedError::LibSmError(format!("{e}")))?;

        self.sign_digest(rng, &digest)
    }

    pub fn sign_digest(
        &self,
        rng: &mut dyn SecureRandom,
        digest: &[u8],
    ) -> Result<Signature, KeyRejectedError> {
        for _ in 0..100 {
            #[allow(unused_variables)]
            let rk = create_private_key(rng)?;

            // todo, the repo in wip state, keep this for testing basic
            // algorithm correctness
            #[cfg(test)]
            let rk = Scalar {
                limbs: [
                    0xd89cdf6229c4bddf,
                    0xacf005cd78843090,
                    0xe5a220abf7212ed6,
                    0xdc30061d04874834,
                ],
                m: PhantomData,
            };

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

            // todo, the repo in wip state, keep this for testing basic
            // algorithm correctness
            #[cfg(test)]
            {
                assert_eq!(
                    r.limbs,
                    [
                        0x343dcb2091bc1f2e,
                        0x66c250abf482e4cb,
                        0xb37a835a2b5a022f,
                        0x76415405cbb177eb
                    ]
                );
                assert_eq!(
                    s.limbs,
                    [
                        0x39b532eb66b9cd90,
                        0x67a1dee839e8179d,
                        0x19073922992c6718,
                        0x61f0665f805e78dd
                    ]
                );
            }

            return Ok(Signature::from_scalars(r, s));
        }
        Err(KeyRejectedError::SignDigestFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_test() {
        let test_word = b"hello world";

        let private_key = b"f68de5710d66195e2bacd994b1408d4e";

        let key_pair = KeyPair::new(private_key).unwrap();

        let sig = key_pair.sign(test_word).unwrap();

        println!(
            "pk: {}, r: {}, s: {}",
            hex::encode(key_pair.pk.bytes_less_safe()),
            hex::encode(&sig.r()),
            hex::encode(&sig.s())
        );

        sig.verify(&key_pair.public_key(), test_word).unwrap()
    }

    #[test]
    fn free_input_verify() {
        let msg = b"hello world";

        let pk = PublicKey::new(
            &hex::decode("B0E4E03D589C97375BBD6EA49483DD976FB88BBB0C07C72827CD8808B5794D5E")
                .unwrap(),
            &hex::decode("2881721E8D9BF56E81FC1E0C325F4FFC052E67FC3A31510D66E7B8749B93B636")
                .unwrap(),
        );

        let sig = Signature::new(
            &hex::decode("45FACCE4BDE9B8A34D43E6060210928802878DDD86A6EAE2938313A165F9F100")
                .unwrap(),
            &hex::decode("D9656DA4EC90FB2EFA399C0ECC6301882CA3301925281C58C2E29D9FD6F9C221")
                .unwrap(),
        )
        .unwrap();

        assert!(sig.verify(&pk, msg).is_ok());
    }
}

#[cfg(feature = "internal_benches")]
mod sign_bench {
    use super::*;
    use rand::prelude::ThreadRng;
    use rand::Rng;

    extern crate test;

    #[bench]
    fn es_sign_bench(bench: &mut test::Bencher) {
        pub struct EgRand(ThreadRng);

        impl SecureRandom for EgRand {
            fn fill(&mut self, dest: &mut [u8]) {
                self.0.fill(dest)
            }
        }

        let test_word = b"hello world";
        let mut rng = EgRand(rand::thread_rng());

        let private_key = b"f68de5710d66195e2bacd994b1408d4e";

        let key_pair = KeyPair::new(private_key).unwrap();

        bench.iter(|| {
            let _ = key_pair.sign_with_seed(&mut rng, test_word).unwrap();
        });
    }

    #[bench]
    fn libsm_sign_bench(bench: &mut test::Bencher) {
        let test_word = b"hello world";
        let ctx = libsm::sm2::signature::SigCtx::new();
        let (pk, sk) = ctx.new_keypair().unwrap();

        bench.iter(|| {
            let _ = ctx.sign(test_word, &sk, &pk);
        });
    }

    #[bench]
    fn es_verify_bench(bench: &mut test::Bencher) {
        pub struct EgRand(ThreadRng);

        impl SecureRandom for EgRand {
            fn fill(&mut self, dest: &mut [u8]) {
                self.0.fill(dest)
            }
        }

        let test_word = b"hello world";
        let mut rng = EgRand(rand::thread_rng());

        let private_key = b"f68de5710d66195e2bacd994b1408d4e";
        let key_pair = KeyPair::new(private_key).unwrap();
        let sig = key_pair.sign_with_seed(&mut rng, test_word).unwrap();
        let pk = key_pair.public_key();

        bench.iter(|| {
            let _ = sig.verify(&pk, test_word).unwrap();
        });
    }

    #[bench]
    fn libsm_verify_bench(bench: &mut test::Bencher) {
        let test_word = b"hello world";
        let ctx = libsm::sm2::signature::SigCtx::new();
        let (pk, sk) = ctx.new_keypair().unwrap();
        let sig = ctx.sign(test_word, &sk, &pk).unwrap();

        bench.iter(|| {
            let _ = ctx.verify(test_word, &pk, &sig);
        });
    }
}
