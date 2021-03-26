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

use crate::key::public::PublicKey;
use crate::limb::{Limb, LIMB_LENGTH, ONE};
use crate::norop::{norop_limbs_equal_with, norop_limbs_less_than};
use crate::sm2p256::{
    add_mod, base_point_mul, inv_sqr, mont_pro, point_add, point_mul, scalar_add_mod, scalar_inv,
    scalar_mont_pro, scalar_sub_mod, CURVE_PARAMS,
};
use core::marker::PhantomData;

// Indicates that the element is not encoded; there is no *R* factor
// that needs to be canceled out.
#[derive(Copy, Clone)]
pub enum Unencoded {}

// Indicates that the element is encoded; the value has one *R*
// factor that needs to be canceled out.
#[derive(Copy, Clone)]
pub enum R {}

// Indicates the element is encoded twice; the value has two *R*
// factors that need to be canceled out.
#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone)]
pub enum RR {}

// Indicates the element is inversely encoded; the value has one
// 1/*R* factor that needs to be canceled out.
#[derive(Copy, Clone)]
pub enum RInverse {}

pub trait Encoding {}

impl Encoding for RR {}
impl Encoding for R {}
impl Encoding for Unencoded {}
impl Encoding for RInverse {}

/// The encoding of the result of a reduction.
pub trait ReductionEncoding {
    type Output: Encoding;
}

impl ReductionEncoding for RR {
    type Output = R;
}
impl ReductionEncoding for R {
    type Output = Unencoded;
}
impl ReductionEncoding for Unencoded {
    type Output = RInverse;
}

/// The encoding of the result of a multiplication.
pub trait ProductEncoding {
    type Output: Encoding;
}

impl<E: ReductionEncoding> ProductEncoding for (Unencoded, E) {
    type Output = E::Output;
}

impl<E: Encoding> ProductEncoding for (R, E) {
    type Output = E;
}

impl<E: ReductionEncoding> ProductEncoding for (RInverse, E)
where
    E::Output: ReductionEncoding,
{
    type Output = <<E as ReductionEncoding>::Output as ReductionEncoding>::Output;
}

// XXX: Rust doesn't allow overlapping impls,
// TODO (if/when Rust allows it):
// impl<E1, E2: ReductionEncoding> ProductEncoding for
//         (E1, E2) {
//     type Output = <(E2, E1) as ProductEncoding>::Output;
// }
impl ProductEncoding for (RR, Unencoded) {
    type Output = <(Unencoded, RR) as ProductEncoding>::Output;
}
impl ProductEncoding for (RR, RInverse) {
    type Output = <(RInverse, RR) as ProductEncoding>::Output;
}

/// Elements are always fully reduced with respect to *m*; i.e.
/// the 0 <= x < m for every value x.
#[derive(Clone, Copy)]
pub struct Elem<M> {
    pub limbs: [Limb; LIMB_LENGTH],

    /// The modulus *m* for the ring ℤ/mℤ for which this element is a value.
    pub m: PhantomData<M>,
}

impl<M> Elem<M> {
    pub fn zero() -> Self {
        Self {
            limbs: [0; LIMB_LENGTH],
            m: PhantomData,
        }
    }

    pub fn is_zero(&self) -> bool {
        norop_limbs_equal_with(&self.limbs, &[0; LIMB_LENGTH])
    }

    pub fn is_equal(&self, other: &Elem<M>) -> bool {
        norop_limbs_equal_with(&self.limbs, &other.limbs)
    }
}

pub fn elem_mul<EA: Encoding, EB: Encoding>(
    a: &Elem<EA>,
    b: &Elem<EB>,
) -> Elem<<(EA, EB) as ProductEncoding>::Output>
where
    (EA, EB): ProductEncoding,
{
    Elem {
        limbs: mont_pro(&a.limbs, &b.limbs),
        m: PhantomData,
    }
}

pub fn elem_add(a: &Elem<R>, b: &Elem<R>) -> Elem<R> {
    Elem {
        limbs: add_mod(&a.limbs, &b.limbs),
        m: PhantomData,
    }
}

pub fn elem_inv_sqr_to_mont(a: &Elem<R>) -> Elem<R> {
    assert!(!norop_limbs_equal_with(&a.limbs, &[0; LIMB_LENGTH]));

    Elem {
        limbs: inv_sqr(&a.limbs),
        m: PhantomData,
    }
}

pub fn elem_to_unencoded(a: &Elem<R>) -> Elem<Unencoded> {
    Elem {
        limbs: mont_pro(&a.limbs, &ONE),
        m: PhantomData,
    }
}

pub fn elem_reduced_to_scalar(e: &Elem<Unencoded>) -> Scalar {
    if norop_limbs_less_than(&e.limbs, &CURVE_PARAMS.n) {
        Scalar {
            limbs: e.limbs,
            m: PhantomData,
        }
    } else {
        Scalar {
            limbs: scalar_sub_mod(&e.limbs, &CURVE_PARAMS.n),
            m: PhantomData,
        }
    }
}

pub fn scalar_to_elem(e: &Scalar) -> Elem<Unencoded> {
    Elem {
        limbs: e.limbs,
        m: PhantomData,
    }
}

pub fn point_x(p: &[Limb; LIMB_LENGTH * 3]) -> Elem<R> {
    let mut r = Elem::zero();
    r.limbs.copy_from_slice(&p[..LIMB_LENGTH]);
    r
}

pub fn point_y(p: &[Limb; LIMB_LENGTH * 3]) -> Elem<R> {
    let mut r = Elem::zero();
    r.limbs.copy_from_slice(&p[LIMB_LENGTH..LIMB_LENGTH * 2]);
    r
}

pub fn point_z(p: &[Limb; LIMB_LENGTH * 3]) -> Elem<R> {
    let mut r = Elem::zero();
    r.limbs.copy_from_slice(&p[LIMB_LENGTH * 2..]);
    r
}

/// A scalar. Its value is in [0, n). Zero-valued scalars are forbidden in most
/// contexts.
pub type Scalar<N = Unencoded> = Elem<N>;

pub fn scalar_inv_to_mont(a: &Scalar) -> Scalar<R> {
    assert!(!norop_limbs_equal_with(&a.limbs, &[0; LIMB_LENGTH]));

    Scalar {
        limbs: scalar_inv(&a.limbs),
        m: PhantomData,
    }
}

pub fn scalar_to_unencoded(a: &Scalar<R>) -> Scalar {
    Scalar {
        limbs: scalar_mont_pro(&a.limbs, &ONE),
        m: PhantomData,
    }
}

pub fn scalar_mul<EA: Encoding, EB: Encoding>(
    a: &Scalar<EA>,
    b: &Scalar<EB>,
) -> Scalar<<(EA, EB) as ProductEncoding>::Output>
where
    (EA, EB): ProductEncoding,
{
    Scalar {
        limbs: scalar_mont_pro(&a.limbs, &b.limbs),
        m: PhantomData,
    }
}

pub fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
    Scalar {
        limbs: scalar_add_mod(&a.limbs, &b.limbs),
        m: PhantomData,
    }
}

pub fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
    Scalar {
        limbs: scalar_sub_mod(&a.limbs, &b.limbs),
        m: PhantomData,
    }
}

fn scalar_g(g_scalar: &Scalar) -> [Limb; LIMB_LENGTH * 3] {
    base_point_mul(&g_scalar.limbs)
}

fn scalar_p(p_scalar: &Scalar, pk: &PublicKey) -> [Limb; LIMB_LENGTH * 3] {
    let point = pk.to_point();
    point_mul(&point, &p_scalar.limbs)
}

pub fn twin_mul(g_scalar: &Scalar, p_scalar: &Scalar, pk: &PublicKey) -> [Limb; LIMB_LENGTH * 3] {
    let g_point = scalar_g(g_scalar);
    let p_point = scalar_p(p_scalar, pk);
    point_add(&g_point, &p_point)
}
