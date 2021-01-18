use crate::limb::{Limb, LIMB_LENGTH};
use crate::norop::{norop_add_pure, norop_limbs_less_than, norop_sub_pure, norop_lmls};
use crate::sm2p256::CURVE_PARAMS;

#[inline]
pub(crate) fn mont_pro_next(a: &[Limb; LIMB_LENGTH], b: &[Limb; LIMB_LENGTH]) -> [Limb; LIMB_LENGTH] {
    let mut r = [0; LIMB_LENGTH];
    let mut c0: u128 = 0;
    let mut c = [0; LIMB_LENGTH + 2];

    let b0: u128 = b[0] as u128;

    for index in 0..LIMB_LENGTH {
        let mut q = c0 + (a[index] as u128) * b0;
        q = q & 0xffff_ffff_ffff_ffff;
        let mut lam1 = [0; LIMB_LENGTH + 1];
        norop_lmls(&mut lam1, a[index], b);
        let mut lam2 = [0; LIMB_LENGTH + 1];
        norop_lmls(&mut lam2, q as u64, &CURVE_PARAMS.p);
        let mut lam3 = [0; LIMB_LENGTH + 2];
        let f = norop_add_pure(&mut lam3, &lam1, &lam2);
        lam3[LIMB_LENGTH + 1] = f as u64;
        let lam4 = c;
        let _ = norop_add_pure(&mut c, &lam4[1..], &lam3);
        c0 = c[1] as u128;
    }

    if c[LIMB_LENGTH + 1] != 0 || !norop_limbs_less_than(&c[1..LIMB_LENGTH + 1], &CURVE_PARAMS.p) {
        let _ = norop_sub_pure(&mut r, &c[1..LIMB_LENGTH + 1], &CURVE_PARAMS.p);
        return r;
    }

    r.copy_from_slice(&c[1..LIMB_LENGTH + 1]);
    r
}
