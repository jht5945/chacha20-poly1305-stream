// Copyright 2015 chacha20-poly1305-aead Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg_attr(feature = "clippy", allow(inline_always))]

#[cfg(feature = "simd")]
macro_rules! transmute_shuffle {
    ($tmp:ident, $shuffle:ident, $vec:expr, $idx:expr) => {
        unsafe {
            use crate::simdty::$tmp;
            use crate::simdint::$shuffle;
            use std::mem::transmute;

            let tmp_i: $tmp = transmute($vec);
            let tmp_o: $tmp = $shuffle(tmp_i, tmp_i, $idx);
            transmute(tmp_o)
        }
    }
}

#[cfg(feature = "simd")] pub mod u32x4;

#[cfg(not(feature = "simd"))]
macro_rules! simd_opt {
    ($vec:ident) => {
        pub mod $vec {
            use crate::simdty::$vec;

            #[inline(always)]
            pub fn rotate_left_const(vec: $vec, n: u32) -> $vec {
                $vec::new(vec.0.rotate_left(n),
                          vec.1.rotate_left(n),
                          vec.2.rotate_left(n),
                          vec.3.rotate_left(n))
            }
        }
    }
}

#[cfg(not(feature = "simd"))] simd_opt!(u32x4);
