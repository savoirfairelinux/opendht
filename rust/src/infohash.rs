// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

use crate::ffi::*;
use std::ffi::CStr;
use std::ffi::CString;
use std::fmt;

pub use crate::ffi::InfoHash;

impl InfoHash {
    pub fn new() -> InfoHash {
        InfoHash { d: [0; 20] }
    }

    pub fn random() -> InfoHash {
        let mut h = InfoHash::new();
        unsafe {
            dht_infohash_random(&mut h);
        }
        h
    }

    pub fn get(data: &str) -> InfoHash {
        let mut h = InfoHash::new();
        unsafe {
            let c_str = CString::new(data).unwrap();
            dht_infohash_get(&mut h, c_str.as_ptr() as *mut u8, data.len());
        }
        h
    }

    pub fn from_bytes(data: &Vec<u8>) -> InfoHash {
        let mut h = InfoHash::new();
        unsafe {
            dht_infohash_get(&mut h, data.as_ptr() as *mut u8, data.len());
        }
        h
    }

    pub fn from_hex(data: &str) -> InfoHash {
        let mut h = InfoHash::new();
        unsafe {
            let c_str = CString::new(data).unwrap();
            dht_infohash_from_hex(&mut h, c_str.as_ptr());
        }
        h
    }

    pub fn is_zero(&self) -> bool {
        unsafe { dht_infohash_is_zero(self) }
    }
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let self_str = CStr::from_ptr(dht_infohash_print(self))
                .to_str()
                .unwrap_or("");
            write!(f, "{}", self_str)
        }
    }
}
