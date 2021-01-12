use crate::limb::{Limb, LIMB_LENGTH};
use crate::norop::{norop_mul_pure, norop_mul_pure_upper, norop_add_pure, norop_limbs_less_than, norop_sub_pure};
use crate::sm2p256::CURVE_PARAMS;

#[inline]
pub(crate) fn mont_pro_test(a: &[Limb; LIMB_LENGTH], b: &[Limb; LIMB_LENGTH]) -> [Limb; LIMB_LENGTH] {
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

    let mut r0: u64 = 0;
    let mut q: u128 = 0;
    let mut c0: u128 = 0;
    let mut C = [0; LIMB_LENGTH + 2];
    let mut carry = false;

    let b0: u128 = b[LIMB_LENGTH - 1] as u128;

    for index in 0..LIMB_LENGTH {
        q = c0 + (a[index] as u128l) * b0;
        q = q & 0xffff_ffff;
        let mut lam1 = [0; LIMB_LENGTH + 1];
        norop_mul_pure(&mut lam1, &[a[index]], b);
        let mut lam2 = [0; LIMB_LENGTH + 1];
        norop_mul_pure(&mut lam2, &[a[index]], b);
    }

    r
}
