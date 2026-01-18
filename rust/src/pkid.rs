// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

use crate::ffi::*;
use std::ffi::CStr;
use std::fmt;

pub use crate::ffi::PkId;

impl fmt::Display for PkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let self_str = CStr::from_ptr(
                    dht_pkid_print(self)
                ).to_str().unwrap_or("");
            write!(f, "{}", self_str)
        }
    }
}