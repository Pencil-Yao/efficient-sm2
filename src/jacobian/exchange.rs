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
    elem_add, elem_inv_sqr_to_mont, elem_mul, elem_to_unencoded, point_x, point_y, point_z, Elem, R,
};
use crate::err::KeyRejected;
use crate::limb::{Limb, LIMB_BYTES, LIMB_LENGTH};
use crate::norop::big_endian_from_limbs;
use crate::sm2p256::CURVE_PARAMS;

pub fn big_endian_affine_from_jacobian(
    x_out: &mut [u8; LIMB_LENGTH * LIMB_BYTES],
    y_out: &mut [u8; LIMB_LENGTH * LIMB_BYTES],
    point: &[Limb; LIMB_LENGTH * 3],
) -> Result<(), KeyRejected> {
    let (x_aff, y_aff) = affine_from_jacobian(&point)?;
    let x = elem_to_unencoded(&x_aff);
    big_endian_from_limbs(&x.limbs, x_out);
    let y = elem_to_unencoded(&y_aff);
    big_endian_from_limbs(&y.limbs, y_out);

    Ok(())
}

pub fn affine_from_jacobian(
    point: &[Limb; LIMB_LENGTH * 3],
) -> Result<(Elem<R>, Elem<R>), KeyRejected> {
    let x = point_x(point);
    let y = point_y(point);
    let z = point_z(point);

    let zz_inv = elem_inv_sqr_to_mont(&z);

    let x_aff = elem_mul(&x, &zz_inv);

    let y_aff = {
        let zzzz_inv = elem_mul(&zz_inv, &zz_inv);
        let zzz_inv = elem_mul(&z, &zzzz_inv);
        elem_mul(&y, &zzz_inv)
    };

    verify_affine_point_is_on_the_curve((&x_aff, &y_aff), &CURVE_PARAMS.a, &CURVE_PARAMS.b)?;

    Ok((x_aff, y_aff))
}

pub fn verify_jacobian_point_is_on_the_curve(
    point: &[Limb; LIMB_LENGTH * 3],
) -> Result<(), KeyRejected> {
    let z = point_z(&point);

    if z.is_zero() {
        return Err(KeyRejected::zero_error());
    }

    let x = point_x(&point);
    let y = point_y(&point);

    let z2 = elem_mul(&z, &z);
    let z4 = elem_mul(&z2, &z2);
    let z4_a = elem_mul(&z4, &CURVE_PARAMS.a);
    let z6 = elem_mul(&z4, &z2);
    let z6_b = elem_mul(&z6, &CURVE_PARAMS.b);

    verify_affine_point_is_on_the_curve((&x, &y), &z4_a, &z6_b)
}

pub fn verify_affine_point_is_on_the_curve(
    (x, y): (&Elem<R>, &Elem<R>),
    a: &Elem<R>,
    b: &Elem<R>,
) -> Result<(), KeyRejected> {
    let lhs = elem_mul(y, y);

    let x2 = elem_mul(x, x);
    let x2_a = elem_add(&x2, a);
    let x2_a_x = elem_mul(&x2_a, x);
    let rhs = elem_add(&x2_a_x, b);

    if !lhs.is_equal(&rhs) {
        return Err(KeyRejected::not_on_curve_error());
    }
    Ok(())
}
