// Copyright 2016 chacha20-poly1305-aead Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::as_bytes::Safe;

#[cfg(feature = "simd")]
macro_rules! decl_simd {
    ($($decl:item)*) => {
        $(
            #[derive(Clone, Copy, Debug, Default)]
            #[repr(simd)]
            $decl
        )*
    }
}

#[cfg(not(feature = "simd"))]
macro_rules! decl_simd {
    ($($decl:item)*) => {
        $(
            #[derive(Clone, Copy, Debug, Default)]
            #[repr(C)]
            $decl
        )*
    }
}

decl_simd! {
    pub struct Simd4<T>(pub T, pub T, pub T, pub T);
    pub struct Simd8<T>(pub T, pub T, pub T, pub T,
                        pub T, pub T, pub T, pub T);
    pub struct Simd16<T>(pub T, pub T, pub T, pub T,
                         pub T, pub T, pub T, pub T,
                         pub T, pub T, pub T, pub T,
                         pub T, pub T, pub T, pub T);
}

pub type u32x4 = Simd4<u32>;
pub type u16x8 = Simd8<u16>;
pub type u8x16 = Simd16<u8>;

#[cfg_attr(feature = "clippy", allow(inline_always))]
impl<T> Simd4<T> {
    #[inline(always)]
    pub fn new(e0: T, e1: T, e2: T, e3: T) -> Simd4<T> {
        Simd4(e0, e1, e2, e3)
    }
}

unsafe impl<T: Safe> Safe for Simd4<T> {}

unsafe impl<T: Safe> Safe for Simd8<T> {}

unsafe impl<T: Safe> Safe for Simd16<T> {}
