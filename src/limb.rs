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

// XXX: Not correct for x32 ABIs.
#[cfg(target_pointer_width = "64")]
pub type Limb = u64;
#[cfg(target_pointer_width = "32")]
pub type Limb = u32;
#[cfg(target_pointer_width = "64")]
pub const LIMB_BITS: usize = 64;
#[cfg(target_pointer_width = "32")]
pub const LIMB_FULL: Limb = 0xffff_ffff;
#[cfg(target_pointer_width = "64")]
pub const LIMB_FULL: Limb = 0xffff_ffff_ffff_ffff;
#[cfg(target_pointer_width = "32")]
pub const LIMB_BITS: usize = 32;
#[cfg(target_pointer_width = "64")]
pub type DoubleLimb = u128;
#[cfg(target_pointer_width = "32")]
pub type DoubleLimb = u64;
#[cfg(target_pointer_width = "64")]
pub const LIMB_LENGTH: usize = 4;
#[cfg(target_pointer_width = "32")]
pub const LIMB_LENGTH: usize = 8;
pub const LIMB_BYTES: usize = (LIMB_BITS + 7) / 8;
#[cfg(target_pointer_width = "64")]
pub const ONE: [Limb; LIMB_LENGTH] = [1, 0, 0, 0];
#[cfg(target_pointer_width = "32")]
pub const ONE: [Limb; LIMB_LENGTH] = [1, 0, 0, 0, 0, 0, 0, 0];
