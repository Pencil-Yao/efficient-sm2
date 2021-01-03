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

use crate::elem::{Elem, R};
use crate::limb::{Limb, LIMB_BITS, LIMB_LENGTH};
use crate::norop::{
    norop_add_pure, norop_limbs_equal_with, norop_limbs_less_than, norop_mul_pure,
    norop_mul_pure_upper, norop_sub_pure,
};
use crate::sm2p256_table::SM2P256_PRECOMPUTED;
use std::marker::PhantomData;

pub static CURVE_PARAMS: CurveParams = CurveParams {
    a: Elem {
        limbs: [
            0xfffffffffffffffc,
            0xfffffffc00000003,
            0xffffffffffffffff,
            0xfffffffbffffffff,
        ],
        m: PhantomData,
    },
    b: Elem {
        limbs: [
            0x90d230632bc0dd42,
            0x71cf379ae9b537ab,
            0x527981505ea51c3c,
            0x240fe188ba20e2c8,
        ],
        m: PhantomData,
    },
    p: [
        0xffffffffffffffff,
        0xffffffff00000000,
        0xffffffffffffffff,
        0xfffffffeffffffff,
    ],
    n: [
        0x53bbf40939d54123,
        0x7203df6b21c6052b,
        0xffffffffffffffff,
        0xfffffffeffffffff,
    ],
    p_inv_r_neg: [
        0x0000000000000001,
        0xffffffff00000001,
        0xfffffffe00000000,
        0xfffffffc00000001,
    ],
    r_p: [
        0x0000000000000001,
        0x00000000ffffffff,
        0x0000000000000000,
        0x100000000,
    ],
    rr_p: [
        0x0000000200000003,
        0x00000002ffffffff,
        0x0000000100000001,
        0x0400000002,
    ],
    n_inv_r_neg: [
        0x327f9e8872350975,
        0xdf1e8d34fc8319a5,
        0x2b0068d3b08941d4,
        0x6f39132f82e4c7bc,
    ],
    rr_n: [
        0x901192af7c114f20,
        0x3464504ade6fa2fa,
        0x620fc84c3affe0d4,
        0x1eb5e412a22b3d3b,
    ],
};

pub struct CurveParams {
    pub a: Elem<R>,
    pub b: Elem<R>,
    pub p: [u64; 4],
    pub n: [u64; 4],
    pub p_inv_r_neg: [u64; 4],
    pub r_p: [u64; 4],
    pub rr_p: [u64; 4],
    pub n_inv_r_neg: [u64; 4],
    pub rr_n: [u64; 4],
}

#[inline]
pub(crate) fn mont_pro(a: &[Limb; LIMB_LENGTH], b: &[Limb; LIMB_LENGTH]) -> [Limb; LIMB_LENGTH] {
    let mut r = [0; LIMB_LENGTH];
    let mut t = [0; LIMB_LENGTH * 2];
    norop_mul_pure(&mut t, a, b);
    norop_mul_pure_upper(&mut r, &t[0..LIMB_LENGTH], &CURVE_PARAMS.p_inv_r_neg, 4);
    let mut lam2 = [0; LIMB_LENGTH * 2];
    norop_mul_pure(&mut lam2, &r, &CURVE_PARAMS.p);
    let mut lam3 = [0; LIMB_LENGTH * 2];
    let carry = norop_add_pure(&mut lam3, &t, &lam2);

    if carry || !norop_limbs_less_than(&lam3[LIMB_LENGTH..], &CURVE_PARAMS.p) {
        let _ = norop_sub_pure(&mut r, &lam3[LIMB_LENGTH..], &CURVE_PARAMS.p);
        return r;
    }

    r.copy_from_slice(&lam3[LIMB_LENGTH..]);
    r
}

#[inline]
pub(crate) fn add_mod(a: &[Limb; LIMB_LENGTH], b: &[Limb; LIMB_LENGTH]) -> [Limb; LIMB_LENGTH] {
    let mut r = [0; LIMB_LENGTH];
    let carry = norop_add_pure(&mut r, a, b);

    if carry || !norop_limbs_less_than(&r, &CURVE_PARAMS.p) {
        let lam1 = r;
        let _ = norop_sub_pure(&mut r, &lam1, &CURVE_PARAMS.p);
        return r;
    }
    r
}

#[inline]
pub(crate) fn sub_mod(a: &[Limb; LIMB_LENGTH], b: &[Limb; LIMB_LENGTH]) -> [Limb; LIMB_LENGTH] {
    let mut r = [0; LIMB_LENGTH];
    let borrow = norop_sub_pure(&mut r, a, b);

    if borrow {
        let lam1 = r;
        let _ = norop_add_pure(&mut r, &lam1, &CURVE_PARAMS.p);
        return r;
    }
    r
}

#[inline]
pub(crate) fn shl(a: &[Limb; LIMB_LENGTH], shift: usize) -> [Limb; LIMB_LENGTH] {
    assert!(shift < 64);
    let m = [1 << shift];

    let mut lam1 = [0; LIMB_LENGTH + 1];
    norop_mul_pure(&mut lam1, a, &m);

    let lam2 = lam1;
    norop_mul_pure(&mut lam1, &lam2[LIMB_LENGTH..], &CURVE_PARAMS.p);

    let lam3 = lam1;
    let _ = norop_sub_pure(&mut lam1, &lam2, &lam3);

    let mut r = [0; LIMB_LENGTH];
    if !norop_limbs_less_than(&lam1, &CURVE_PARAMS.p) {
        let lam4 = lam1;
        let _ = norop_sub_pure(&mut lam1, &lam4, &CURVE_PARAMS.p);
    }
    r.copy_from_slice(&lam1[..LIMB_LENGTH]);
    r
}

#[cfg(test)]
#[inline]
pub(crate) fn shl_bak(a: &[Limb; LIMB_LENGTH], shift: usize) -> [Limb; LIMB_LENGTH] {
    assert!(shift < 256);
    let mut mid = [0; LIMB_LENGTH];

    mid[shift / LIMB_BITS] = 1 << (shift % LIMB_BITS);

    let b = to_mont(&mid);
    mont_pro(a, &b)
}

#[inline]
pub(crate) fn to_jacobi(
    x: &[Limb; LIMB_LENGTH],
    y: &[Limb; LIMB_LENGTH],
) -> [Limb; LIMB_LENGTH * 3] {
    let mut r = [0; LIMB_LENGTH * 3];

    r[..LIMB_LENGTH].copy_from_slice(x);
    r[LIMB_LENGTH..LIMB_LENGTH * 2].copy_from_slice(y);
    // 1 * r modsm2p256
    r[LIMB_LENGTH * 2..].copy_from_slice(&[
        0x0000000000000001,
        0x00000000ffffffff,
        0x0000000000000000,
        0x0100000000,
    ]);

    r
}

#[inline]
pub(crate) fn to_mont(a: &[Limb; LIMB_LENGTH]) -> [Limb; LIMB_LENGTH] {
    mont_pro(a, &CURVE_PARAMS.rr_p)
}

// (`a` squared `squarings` times) * b
fn sqr_mul(
    a: &[Limb; LIMB_LENGTH],
    b: &[Limb; LIMB_LENGTH],
    squarings: usize,
) -> [Limb; LIMB_LENGTH] {
    let mut r = mont_pro(a, a);
    for _ in 1..squarings {
        r = mont_pro(&r, &r);
    }
    mont_pro(&r, b)
}

#[inline]
pub(crate) fn point_add(
    a: &[Limb; LIMB_LENGTH * 3],
    b: &[Limb; LIMB_LENGTH * 3],
) -> [Limb; LIMB_LENGTH * 3] {
    let mut r = [0; LIMB_LENGTH * 3];

    let mut a_x = [0; LIMB_LENGTH];
    a_x.copy_from_slice(&a[..LIMB_LENGTH]);
    let mut a_y = [0; LIMB_LENGTH];
    a_y.copy_from_slice(&a[LIMB_LENGTH..LIMB_LENGTH * 2]);
    let mut a_z = [0; LIMB_LENGTH];
    a_z.copy_from_slice(&a[2 * LIMB_LENGTH..]);

    let mut b_x = [0; LIMB_LENGTH];
    b_x.copy_from_slice(&b[..LIMB_LENGTH]);
    let mut b_y = [0; LIMB_LENGTH];
    b_y.copy_from_slice(&b[LIMB_LENGTH..LIMB_LENGTH * 2]);
    let mut b_z = [0; LIMB_LENGTH];
    b_z.copy_from_slice(&b[2 * LIMB_LENGTH..]);

    if norop_limbs_equal_with(&a_z, &[0]) {
        return *b;
    } else if norop_limbs_equal_with(&b_z, &[0]) {
        return *a;
    } else if norop_limbs_equal_with(&a_x, &b_x)
        && norop_limbs_equal_with(&a_y, &b_y)
        && norop_limbs_equal_with(&a_z, &b_z)
    {
        return point_double(a);
    }

    let a_z_sqr = mont_pro(&a_z, &a_z);
    let b_z_sqr = mont_pro(&b_z, &b_z);
    let u1 = mont_pro(&a_x, &b_z_sqr);
    let u2 = mont_pro(&b_x, &a_z_sqr);
    let a_z_cub = mont_pro(&a_z_sqr, &a_z);
    let b_z_cub = mont_pro(&b_z_sqr, &b_z);
    let s1 = mont_pro(&a_y, &b_z_cub);
    let s2 = mont_pro(&b_y, &a_z_cub);
    let h = sub_mod(&u2, &u1);
    let r2 = sub_mod(&s2, &s1);
    let r2_sqr = mont_pro(&r2, &r2);
    let h_sqr = mont_pro(&h, &h);
    let h_cub = mont_pro(&h_sqr, &h);

    let vu = mont_pro(&u1, &h_sqr); // u1*hh
    let lam1 = sub_mod(&r2_sqr, &h_cub); // rr-hhh
    let lam2 = add_mod(&vu, &vu); // 2*v
    let r_x = sub_mod(&lam1, &lam2); // x3=rr-hhh-2*v

    let lam3 = sub_mod(&vu, &r_x); // v-x3
    let lam4 = mont_pro(&r2, &lam3); // r*(v-x3)
    let lam5 = mont_pro(&s1, &h_cub); // s1*hhh
    let r_y = sub_mod(&lam4, &lam5); // y3=r*(v-x3)-s1*hhh

    let lam6 = mont_pro(&a_z, &b_z);
    let r_z = mont_pro(&lam6, &h);

    r[..LIMB_LENGTH].copy_from_slice(&r_x);
    r[LIMB_LENGTH..LIMB_LENGTH * 2].copy_from_slice(&r_y);
    r[LIMB_LENGTH * 2..].copy_from_slice(&r_z);
    r
}

#[inline]
pub(crate) fn point_double(a: &[Limb; LIMB_LENGTH * 3]) -> [Limb; LIMB_LENGTH * 3] {
    let mut r = [0; LIMB_LENGTH * 3];

    let mut a_x = [0; LIMB_LENGTH];
    a_x.copy_from_slice(&a[..LIMB_LENGTH]);
    let mut a_y = [0; LIMB_LENGTH];
    a_y.copy_from_slice(&a[LIMB_LENGTH..LIMB_LENGTH * 2]);
    let mut a_z = [0; LIMB_LENGTH];
    a_z.copy_from_slice(&a[2 * LIMB_LENGTH..]);

    let delta = mont_pro(&a_z, &a_z);
    let gamma = mont_pro(&a_y, &a_y);
    let beta = mont_pro(&a_x, &gamma);
    let lam1 = sub_mod(&a_x, &delta); // x1-delta
    let lam2 = add_mod(&a_x, &delta); // x1+delta
    let lam3 = mont_pro(&lam1, &lam2); // (x1-delta)*(x1+delta)
    let lam4 = add_mod(&lam3, &lam3); // 2(x1-delta)*(x1+delta)
    let alpha = add_mod(&lam3, &lam4); // 3(x1-delta)*(x1+delta)
    let lam5 = mont_pro(&alpha, &alpha); // alpha^2
    let lam6_m1 = add_mod(&beta, &beta); // 2beta
    let lam6_m2 = add_mod(&lam6_m1, &lam6_m1); // 4beta
    let lam6 = add_mod(&lam6_m2, &lam6_m2); // 8beta
    let r_x = sub_mod(&lam5, &lam6); // x3=alpha^2-8beta

    let lam7 = add_mod(&a_y, &a_z);
    let lam8 = mont_pro(&lam7, &lam7); // (y1+z1)^2
    let lam9 = sub_mod(&lam8, &gamma); // (y1+z1)^2-gamma
    let r_z = sub_mod(&lam9, &delta);

    let lam11 = sub_mod(&lam6_m2, &r_x); // 4beat-x3
    let lam12 = mont_pro(&alpha, &lam11); // alpha*(4*beta-x3)
    let gamma_sqr = mont_pro(&gamma, &gamma);
    let lam13 = shl(&gamma_sqr, 3); // 8gamma^2
    let r_y = sub_mod(&lam12, &lam13);

    r[..LIMB_LENGTH].copy_from_slice(&r_x);
    r[LIMB_LENGTH..LIMB_LENGTH * 2].copy_from_slice(&r_y);
    r[LIMB_LENGTH * 2..].copy_from_slice(&r_z);
    r
}

#[allow(clippy::eq_op)]
#[inline]
pub(crate) fn point_mul(
    a: &[Limb; LIMB_LENGTH * 3],
    scalar: &[Limb; LIMB_LENGTH],
) -> [Limb; LIMB_LENGTH * 3] {
    let mut r = [0; LIMB_LENGTH * 3];

    let mut table = [[0; LIMB_LENGTH * 3]; 15];

    table[1 - 1] = *a;
    table[2 - 1] = point_double(&table[1 - 1]);
    table[4 - 1] = point_double(&table[2 - 1]);
    table[8 - 1] = point_double(&table[4 - 1]);
    table[3 - 1] = point_add(&table[1 - 1], &table[2 - 1]);
    table[6 - 1] = point_double(&table[3 - 1]);
    table[7 - 1] = point_add(&table[1 - 1], &table[6 - 1]);
    table[12 - 1] = point_double(&table[6 - 1]);
    table[5 - 1] = point_add(&table[1 - 1], &table[4 - 1]);
    table[10 - 1] = point_double(&table[5 - 1]);
    table[14 - 1] = point_double(&table[7 - 1]);
    table[9 - 1] = point_add(&table[1 - 1], &table[8 - 1]);
    table[11 - 1] = point_add(&table[1 - 1], &table[10 - 1]);
    table[13 - 1] = point_add(&table[1 - 1], &table[12 - 1]);
    table[15 - 1] = point_add(&table[1 - 1], &table[14 - 1]);

    for i in 0..scalar.len() {
        for j in 0..LIMB_BITS / 4 {
            let index = scalar[LIMB_LENGTH - 1 - i] >> ((LIMB_BITS / 4 - 1 - j) * 4);
            if index & 0x0f != 0 {
                r = point_add(&table[((index - 1) & 0x0f) as usize], &r)
            }

            if i + 1 == scalar.len() && j + 1 == LIMB_BITS / 4 {
                break;
            }

            r = point_double(&r);
            r = point_double(&r);
            r = point_double(&r);
            r = point_double(&r);
        }
    }

    r
}

#[cfg(test)]
#[inline]
pub(crate) fn point_mul_bak(
    a: &[Limb; LIMB_LENGTH * 3],
    scalar: &[Limb; LIMB_LENGTH],
) -> [Limb; LIMB_LENGTH * 3] {
    let mut r = [0; LIMB_LENGTH * 3];
    let mut a = *a;

    for scalar_word in scalar {
        let mut bit: usize = 0;
        while bit < LIMB_BITS {
            if (scalar_word >> bit) & 0x01 != 0 {
                r = point_add(&r, &a);
            }
            a = point_double(&a);
            bit += 1;
        }
    }

    r
}

#[inline]
pub(crate) fn base_point_mul(scalar: &[Limb; LIMB_LENGTH]) -> [Limb; LIMB_LENGTH * 3] {
    let mut r = [0; LIMB_LENGTH * 3];
    let num = LIMB_BITS / 8;

    for (index, scalar_word) in scalar.iter().enumerate() {
        for m in 0..num {
            let raw_index = ((scalar_word >> (8 * m)) & 0xff) as usize;
            if raw_index != 0 {
                let a = to_jacobi(
                    &SM2P256_PRECOMPUTED[num * index + m][raw_index * 2 - 2],
                    &SM2P256_PRECOMPUTED[num * index + m][raw_index * 2 - 1],
                );
                r = point_add(&r, &a);
            }
        }
    }

    r
}

#[inline]
pub(crate) fn inv_sqr(a: &[Limb; LIMB_LENGTH]) -> [Limb; LIMB_LENGTH] {
    // Calculate a**-2 (mod q) == a**(q - 3) (mod q)
    //
    // The exponent (q - 3) is:
    //
    //    0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc

    let b_1 = &a;
    let b_11 = sqr_mul(b_1, b_1, 1);
    let b_111 = sqr_mul(&b_11, b_1, 1);
    let f_11 = sqr_mul(&b_111, &b_111, 3);
    let fff = sqr_mul(&f_11, &f_11, 6);
    let fff_111 = sqr_mul(&fff, &b_111, 3);
    let fffffff_11 = sqr_mul(&fff_111, &fff_111, 15);
    let ffffffff = sqr_mul(&fffffff_11, &b_11, 2);

    // fffffff_111
    let mut acc = sqr_mul(&fffffff_11, &b_1, 1);

    // fffffffe
    acc = mont_pro(&acc, &acc);

    // fffffffeffffffff
    acc = sqr_mul(&acc, &ffffffff, 32);

    // fffffffeffffffffffffffff
    acc = sqr_mul(&acc, &ffffffff, 32);

    // fffffffeffffffffffffffffffffffff
    acc = sqr_mul(&acc, &ffffffff, 32);

    // fffffffeffffffffffffffffffffffffffffffff
    acc = sqr_mul(&acc, &ffffffff, 32);

    // fffffffeffffffffffffffffffffffffffffffff00000000ffffffff
    acc = sqr_mul(&acc, &ffffffff, 64);

    // fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffff_11
    acc = sqr_mul(&acc, &fffffff_11, 30);

    // fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc
    acc = mont_pro(&acc, &acc);
    mont_pro(&acc, &acc)
}

#[inline]
pub(crate) fn scalar_to_mont(a: &[Limb; LIMB_LENGTH]) -> [Limb; LIMB_LENGTH] {
    scalar_mont_pro(a, &CURVE_PARAMS.rr_n)
}

// `a` squared `squarings` times
#[inline]
fn scalar_sqr_mul(
    a: &[Limb; LIMB_LENGTH],
    b: &[Limb; LIMB_LENGTH],
    squarings: usize,
) -> [Limb; LIMB_LENGTH] {
    let mut r = scalar_mont_pro(a, a);
    for _ in 1..squarings {
        r = scalar_mont_pro(&r, &r);
    }

    scalar_mont_pro(&r, b)
}

#[inline]
pub(crate) fn scalar_mont_pro(
    a: &[Limb; LIMB_LENGTH],
    b: &[Limb; LIMB_LENGTH],
) -> [Limb; LIMB_LENGTH] {
    let mut r = [0; LIMB_LENGTH];
    let mut t = [0; LIMB_LENGTH * 2];
    norop_mul_pure(&mut t, a, b);
    norop_mul_pure_upper(&mut r, &t[0..LIMB_LENGTH], &CURVE_PARAMS.n_inv_r_neg, 4);
    let mut lam2 = [0; LIMB_LENGTH * 2];
    norop_mul_pure(&mut lam2, &r, &CURVE_PARAMS.n);
    let mut lam3 = [0; LIMB_LENGTH * 2];
    let carry = norop_add_pure(&mut lam3, &t, &lam2);

    if carry || !norop_limbs_less_than(&lam3[LIMB_LENGTH..], &CURVE_PARAMS.n) {
        let _ = norop_sub_pure(&mut r, &lam3[LIMB_LENGTH..], &CURVE_PARAMS.n);
        return r;
    }

    r.copy_from_slice(&lam3[LIMB_LENGTH..]);
    r
}

#[inline]
pub(crate) fn scalar_add_mod(
    a: &[Limb; LIMB_LENGTH],
    b: &[Limb; LIMB_LENGTH],
) -> [Limb; LIMB_LENGTH] {
    let mut r = [0; LIMB_LENGTH];
    let carry = norop_add_pure(&mut r, a, b);

    if carry || !norop_limbs_less_than(&r, &CURVE_PARAMS.n) {
        let lam1 = r;
        let _ = norop_sub_pure(&mut r, &lam1, &CURVE_PARAMS.n);
        return r;
    }
    r
}

#[inline]
pub(crate) fn scalar_sub_mod(
    a: &[Limb; LIMB_LENGTH],
    b: &[Limb; LIMB_LENGTH],
) -> [Limb; LIMB_LENGTH] {
    let mut r = [0; LIMB_LENGTH];
    let borrow = norop_sub_pure(&mut r, a, b);

    if borrow {
        let lam1 = r;
        let _ = norop_add_pure(&mut r, &lam1, &CURVE_PARAMS.n);
        return r;
    }
    r
}

#[inline]
#[allow(clippy::identity_op)]
pub(crate) fn scalar_inv(a: &[Limb; LIMB_LENGTH]) -> [Limb; LIMB_LENGTH] {
    // Calculate the modular inverse of scalar |a| using Fermat's Little
    // Theorem:
    //
    //    a**-1 (mod n) == a**(n - 2) (mod n)
    //
    // The exponent (n - 2) is:
    //
    //    0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121

    // Indexes into `d`.
    const B_1: usize = 0;
    const B_10: usize = 1;
    const B_11: usize = 2;
    const B_101: usize = 3;
    const B_111: usize = 4;
    const B_1111: usize = 5;
    const B_10101: usize = 6;
    const B_101111: usize = 7;
    const DIGIT_COUNT: usize = 8;

    let mut d = [[0; LIMB_LENGTH]; DIGIT_COUNT];

    d[B_1] = scalar_to_mont(a);
    d[B_10] = scalar_mont_pro(&d[B_1], &d[B_1]);
    d[B_11] = scalar_mont_pro(&d[B_10], &d[B_1]);
    d[B_101] = scalar_mont_pro(&d[B_10], &d[B_11]);
    d[B_111] = scalar_mont_pro(&d[B_101], &d[B_10]);
    let b_1010 = scalar_mont_pro(&d[B_101], &d[B_101]);
    d[B_1111] = scalar_mont_pro(&b_1010, &d[B_101]);
    d[B_10101] = scalar_sqr_mul(&b_1010, &d[B_1], 0 + 1);
    let b_101010 = scalar_mont_pro(&d[B_10101], &d[B_10101]);
    d[B_101111] = scalar_mont_pro(&b_101010, &d[B_101]);
    let b_111111 = scalar_mont_pro(&b_101010, &d[B_10101]);
    let b_1111111 = scalar_sqr_mul(&b_111111, &d[B_1], 0 + 1);

    let ff = scalar_sqr_mul(&b_111111, &d[B_11], 0 + 2);
    let ffff = scalar_sqr_mul(&ff, &ff, 0 + 8);
    let ffffffff = scalar_sqr_mul(&ffff, &ffff, 0 + 16);

    // ffffff
    let mut acc = scalar_sqr_mul(&ffff, &ff, 0 + 8);

    // fffffff_111
    acc = scalar_sqr_mul(&acc, &b_1111111, 0 + 7);

    // fffffffe
    acc = scalar_mont_pro(&acc, &acc);

    // fffffffeffffffff
    acc = scalar_sqr_mul(&acc, &ffffffff, 0 + 32);

    // fffffffeffffffffffffffff
    acc = scalar_sqr_mul(&acc, &ffffffff, 0 + 32);

    // fffffffeffffffffffffffffffffffff
    acc = scalar_sqr_mul(&acc, &ffffffff, 0 + 32);

    // The rest of the exponent, in binary, is:
    //
    //    0111,001,00000001111,01111,101,10101,1,001,0000111,00011,000000101,0010101,1
    //    111,1,00111,0111,00111,0010101,1,0000101111,11,00011,00011,001,0010101,001111

    //    0111,001,00000001111,01111,101,10101,1,001,0000111,00011,000000101,0010101,
    //    10101,00111,0111,01111,11,01,0000001,001,00111,00111,010101,01,000001,001,00001

    static REMAINING_WINDOWS: [(usize, usize); 27] = [
        (1 + 3, B_111),
        (2 + 1, B_1),
        (7 + 4, B_1111),
        (1 + 4, B_1111),
        (0 + 3, B_101),
        (0 + 5, B_10101),
        (0 + 1, B_1),
        (2 + 1, B_1),
        (4 + 3, B_111),
        (3 + 2, B_11),
        (6 + 3, B_101),
        (2 + 5, B_10101),
        (0 + 5, B_10101),
        (2 + 3, B_111),
        (1 + 3, B_111),
        (1 + 4, B_1111),
        (0 + 2, B_11),
        (1 + 1, B_1),
        (6 + 1, B_1),
        (2 + 1, B_1),
        (2 + 3, B_111),
        (2 + 3, B_111),
        (1 + 5, B_10101),
        (1 + 1, B_1),
        (5 + 1, B_1),
        (2 + 1, B_1),
        (4 + 1, B_1),
    ];

    for &(squarings, digit) in &REMAINING_WINDOWS {
        acc = scalar_sqr_mul(&acc, &d[digit], squarings);
    }

    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jacobian::exchange::affine_from_jacobian;

    #[test]
    fn sqr_mul_test() {
        let a: &[Limb; LIMB_LENGTH] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let b: &[Limb; LIMB_LENGTH] = &[
            0x16553623adc0a99a,
            0xd3f55c3f46cdfd75,
            0x7bdb6926ab664658,
            0x52ab139ac09ec830,
        ];
        let mut r = sqr_mul(a, b, 4);
        r.reverse();
        println!("sqr_mul_test: {:x?}", r);
    }

    #[test]
    fn mont_pro_test() {
        let a: &[Limb; LIMB_LENGTH] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let mut r = mont_pro(a, a);
        r.reverse();
        println!("mont_pro_test 1: {:x?}", r);

        // 0100000000000000000000000000000000ffffffff0000000000000001 1 * r modsm2p256
        let b: &[Limb; LIMB_LENGTH] = &[
            0x0000000000000001,
            0x00000000ffffffff,
            0x0000000000000000,
            0x0100000000,
        ];
        r = mont_pro(a, b);
        r.reverse();
        println!("mont_pro_test 2: {:x?}", r);
    }

    #[test]
    fn to_mont_test() {
        let a: &[Limb; LIMB_LENGTH] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let mut r = to_mont(a);
        r.reverse();
        println!("to_mont_test: {:x?}", r);
    }

    #[test]
    fn sub_mod_test() {
        let a: &[Limb; LIMB_LENGTH] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let b: &[Limb; LIMB_LENGTH] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let mut r = sub_mod(a, b);
        r.reverse();
        println!("sub_mod_test 1: {:x?}", r);

        let a: &[Limb; LIMB_LENGTH] = &[
            0x0000000000000001,
            0x0000000100000000,
            0x0000000000000000,
            0x0100000000,
        ];
        let b: &[Limb; LIMB_LENGTH] = &[
            0xffffffffffffffff,
            0xffffffff00000001,
            0xffffffffffffffff,
            0xfffffffeffffffff,
        ];
        let mut r = sub_mod(a, b);
        r.reverse();
        println!("sub_mod_test 2: {:x?}", r);
    }

    #[test]
    fn point_double_test() {
        let ori_point_g_x: &[Limb; LIMB_LENGTH] = &[
            0x715a4589334c74c7,
            0x8fe30bbff2660be1,
            0x5f9904466a39c994,
            0x32c4ae2c1f198119,
        ];
        let ori_point_g_y: &[Limb; LIMB_LENGTH] = &[
            0x02df32e52139f0a0,
            0xd0a9877cc62a4740,
            0x59bdcee36b692153,
            0xbc3736a2f4f6779c,
        ];
        let mont_ori_point_g_x = to_mont(ori_point_g_x);
        let mont_ori_point_g_y = to_mont(ori_point_g_y);
        let projective_mont_point_g = to_jacobi(&mont_ori_point_g_x, &mont_ori_point_g_y);
        let double_projective_mont_point_g = point_double(&projective_mont_point_g);

        let r_x: &mut [Limb; LIMB_LENGTH] = &mut [0, 0, 0, 0];
        let r_y: &mut [Limb; LIMB_LENGTH] = &mut [0, 0, 0, 0];
        r_x.copy_from_slice(&double_projective_mont_point_g[..LIMB_LENGTH]);
        r_y.copy_from_slice(&double_projective_mont_point_g[LIMB_LENGTH..LIMB_LENGTH * 2]);
        r_x.reverse();
        r_y.reverse();
        println!("point_double_test: x: {:x?}, y: {:x?}", r_x, r_y);
    }

    #[test]
    fn point_add_test() {
        let g_2_x: &[Limb; LIMB_LENGTH] = &[
            0x0af037bfbc3be46a,
            0x83bdc9ba2d8fa938,
            0x5349d94b5788cd24,
            0x0d7e9c18caa5736a,
        ];
        let g_2_y: &[Limb; LIMB_LENGTH] = &[
            0x6a7e1a1d69db9ac1,
            0xccbd8d37c4a8e82b,
            0xc7b145169b7157ac,
            0x947e74656c21bdf5,
        ];
        let g_4_x: &[Limb; LIMB_LENGTH] = &[
            0x393f7c5a98615060,
            0x487ea27fe9016209,
            0x8a86bcb4a09f9020,
            0x50dc8e3ac899dbe1,
        ];
        let g_4_y: &[Limb; LIMB_LENGTH] = &[
            0xfc099043fd619998,
            0x1de135ea7c7383bd,
            0x4d0bd55632cf70ed,
            0x6ffc31c525bce9e3,
        ];
        let pro_g_2 = to_jacobi(&g_2_x, &g_2_y);
        let pro_g_4 = to_jacobi(&g_4_x, &g_4_y);
        let pro_g_6 = point_add(&pro_g_2, &pro_g_4);

        let r_x: &mut [Limb; LIMB_LENGTH] = &mut [0, 0, 0, 0];
        let r_y: &mut [Limb; LIMB_LENGTH] = &mut [0, 0, 0, 0];
        r_x.copy_from_slice(&pro_g_6[..LIMB_LENGTH]);
        r_y.copy_from_slice(&pro_g_6[LIMB_LENGTH..LIMB_LENGTH * 2]);
        r_x.reverse();
        r_y.reverse();
        println!("point_add_test: x: {:x?}, y: {:x?}", r_x, r_y);
    }

    #[test]
    fn point_mul_test() {
        let ori_point_g_x: &[Limb; LIMB_LENGTH] = &[
            0x715a4589334c74c7,
            0x8fe30bbff2660be1,
            0x5f9904466a39c994,
            0x32c4ae2c1f198119,
        ];
        let ori_point_g_y: &[Limb; LIMB_LENGTH] = &[
            0x02df32e52139f0a0,
            0xd0a9877cc62a4740,
            0x59bdcee36b692153,
            0xbc3736a2f4f6779c,
        ];
        let mont_ori_point_g_x = to_mont(&ori_point_g_x);
        let mont_ori_point_g_y = to_mont(&ori_point_g_y);
        let projective_mont_point_g = to_jacobi(&mont_ori_point_g_x, &mont_ori_point_g_y);
        let scalar: &[Limb; LIMB_LENGTH] = &[
            0xd89cdf6229c4bddf,
            0xacf005cd78843090,
            0xe5a220abf7212ed6,
            0xdc30061d04874834,
        ];
        let pro_point = point_mul(&projective_mont_point_g, scalar);

        let mut aff_point = affine_from_jacobian(&pro_point).unwrap();
        aff_point.0.limbs.reverse();
        aff_point.1.limbs.reverse();
        println!(
            "point_mul_test: x: {:x?}, y: {:x?}",
            aff_point.0.limbs, aff_point.1.limbs
        );
    }

    #[test]
    fn point_mul_bak_test() {
        let ori_point_g_x: &[Limb; LIMB_LENGTH] = &[
            0x715a4589334c74c7,
            0x8fe30bbff2660be1,
            0x5f9904466a39c994,
            0x32c4ae2c1f198119,
        ];
        let ori_point_g_y: &[Limb; LIMB_LENGTH] = &[
            0x02df32e52139f0a0,
            0xd0a9877cc62a4740,
            0x59bdcee36b692153,
            0xbc3736a2f4f6779c,
        ];
        let mont_ori_point_g_x = to_mont(&ori_point_g_x);
        let mont_ori_point_g_y = to_mont(&ori_point_g_y);
        let projective_mont_point_g = to_jacobi(&mont_ori_point_g_x, &mont_ori_point_g_y);
        let scalar: &[Limb; LIMB_LENGTH] = &[
            0xd89cdf6229c4bddf,
            0xacf005cd78843090,
            0xe5a220abf7212ed6,
            0xdc30061d04874834,
        ];
        let pro_point = point_mul_bak(&projective_mont_point_g, scalar);

        let mut aff_point = affine_from_jacobian(&pro_point).unwrap();
        aff_point.0.limbs.reverse();
        aff_point.1.limbs.reverse();
        println!(
            "point_mul_test: x: {:x?}, y: {:x?}",
            aff_point.0.limbs, aff_point.1.limbs
        );
    }

    #[test]
    fn base_point_mul_test() {
        let scalar: &[Limb; LIMB_LENGTH] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let pro_point = base_point_mul(scalar);

        let mut aff_point = affine_from_jacobian(&pro_point).unwrap();
        aff_point.0.limbs.reverse();
        aff_point.1.limbs.reverse();
        println!(
            "base_point_mul_test: x: {:x?}, y: {:x?}",
            aff_point.0.limbs, aff_point.1.limbs
        );
    }

    #[test]
    fn scalar_mont_pro_test() {
        let a: &[Limb; LIMB_LENGTH] = &[1, 0, 0, 0];
        let b: &[Limb; LIMB_LENGTH] = &[
            0x53bbf40939d54122,
            0x7203df6b21c6052b,
            0xffffffffffffffff,
            0xfffffffeffffffff,
        ];
        let mut r = scalar_mont_pro(a, b);
        r.reverse();
        println!("scalar_mont_pro_test: {:x?}", r);
    }

    #[test]
    fn shl_test() {
        let a: &[Limb; LIMB_LENGTH] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let mut r = shl(a, 7);
        r.reverse();
        println!("shl_test: {:x?}", r);
    }

    #[test]
    fn shl_bak_test() {
        let a: &[Limb; LIMB_LENGTH] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let mut r = shl_bak(a, 7);
        r.reverse();
        println!("shl_test: {:x?}", r);
    }
}

#[cfg(feature = "internal_benches")]
mod sm2_bench {
    use super::*;
    use num_bigint::BigUint;

    extern crate test;

    #[bench]
    fn mont_pro_bench(bench: &mut test::Bencher) {
        let mut a = [
            0xffffff8a00000051,
            0xffffffdc00000054,
            0xffffffba00000031,
            0xffffffc400000063,
        ];
        bench.iter(|| {
            a = mont_pro(&a, &a);
        });
    }

    #[bench]
    fn big_number_bench(bench: &mut test::Bencher) {
        let mut a = BigUint::from_bytes_be(
            &hex::decode("ffffffc400000063ffffffba00000031ffffffdc00000054ffffff8a00000051")
                .unwrap(),
        );
        let p = &BigUint::from_bytes_be(
            &hex::decode("fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff")
                .unwrap(),
        );
        bench.iter(|| {
            a = &a * &a % p;
        });
    }

    #[bench]
    fn libsm_mul_mod_bench(bench: &mut test::Bencher) {
        let ctx = libsm::sm2::field::FieldCtx::new();
        let mut a = libsm::sm2::field::FieldElem::new([
            0xffff_ff8a,
            0x0000_0051,
            0xffff_ffdc,
            0x0000_0054,
            0xffff_ffba,
            0x0000_0031,
            0xffff_ffc4,
            0x0000_0063,
        ]);
        bench.iter(|| {
            a = ctx.mul(&a, &a);
        });
    }

    #[bench]
    fn shl_bench(bench: &mut test::Bencher) {
        let mut a = [
            0xffffff8a00000051,
            0xffffffdc00000054,
            0xffffffba00000031,
            0xffffffc400000063,
        ];
        bench.iter(|| {
            a = shl(&a, 3);
        });
    }

    #[bench]
    fn shl_bak_bench(bench: &mut test::Bencher) {
        let mut a = [
            0xffffff8a00000051,
            0xffffffdc00000054,
            0xffffffba00000031,
            0xffffffc400000063,
        ];
        bench.iter(|| {
            a = shl_bak(&a, 3);
        });
    }

    #[bench]
    fn add_mod_bench(bench: &mut test::Bencher) {
        let mut a = [
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let b = [
            0x16553623adc0a99a,
            0xd3f55c3f46cdfd75,
            0x7bdb6926ab664658,
            0x52ab139ac09ec830,
        ];
        bench.iter(|| {
            a = add_mod(&a, &b);
        });
    }

    #[bench]
    fn sub_mod_bench(bench: &mut test::Bencher) {
        let mut a = [
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let b = [
            0x16553623adc0a99a,
            0xd3f55c3f46cdfd75,
            0x7bdb6926ab664658,
            0x52ab139ac09ec830,
        ];
        bench.iter(|| {
            a = sub_mod(&a, &b);
        });
    }

    #[bench]
    fn point_add_bench(bench: &mut test::Bencher) {
        let mut pro_g_2 = [
            0x18a9143c79e730d4,
            0x5fedb60175ba95fc,
            0x7762251079fb732b,
            0xa53755c618905f76,
            0xce95560addf25357,
            0xba19e45c8b4ab8e4,
            0xdd21f325d2e88688,
            0x25885d858571ff18,
            0x0000000000000001,
            0xffffffff00000000,
            0xffffffffffffffff,
            0xfffffffe,
        ];
        bench.iter(|| {
            pro_g_2 = point_add(&pro_g_2, &pro_g_2);
        });
    }

    #[bench]
    fn point_double_bench(bench: &mut test::Bencher) {
        let mut pro_g_2 = [
            0x18a9143c79e730d4,
            0x5fedb60175ba95fc,
            0x7762251079fb732b,
            0xa53755c618905f76,
            0xce95560addf25357,
            0xba19e45c8b4ab8e4,
            0xdd21f325d2e88688,
            0x25885d858571ff18,
            0x0000000000000001,
            0xffffffff00000000,
            0xffffffffffffffff,
            0xfffffffe,
        ];
        bench.iter(|| {
            pro_g_2 = point_double(&pro_g_2);
        });
    }

    #[bench]
    fn point_mul_bench(bench: &mut test::Bencher) {
        let scalar = [
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        let mut g_2 = [
            0x0af037bfbc3be46a,
            0x83bdc9ba2d8fa938,
            0x5349d94b5788cd24,
            0x0d7e9c18caa5736a,
            0x6a7e1a1d69db9ac1,
            0xccbd8d37c4a8e82b,
            0xc7b145169b7157ac,
            0x947e74656c21bdf5,
            0x0000000000000001,
            0xffffffff00000000,
            0xffffffffffffffff,
            0xfffffffe,
        ];
        bench.iter(|| {
            g_2 = point_mul(&g_2, &scalar);
        });
    }

    #[bench]
    fn base_point_mul_bench(bench: &mut test::Bencher) {
        let scalar = [
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];
        bench.iter(|| {
            let _ = base_point_mul(&scalar);
        });
    }
}
