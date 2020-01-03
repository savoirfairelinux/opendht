/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use crate::ffi::*;
use std::ffi::CStr;
use std::ffi::CString;
use std::fmt;

pub use crate::ffi::InfoHash;

impl InfoHash {
    pub fn new() -> InfoHash {
        InfoHash {
            d: [0; 20]
        }
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
        unsafe {
            dht_infohash_is_zero(self)
        }
    }
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let self_str = CStr::from_ptr(
                    dht_infohash_print(self)
                ).to_str().unwrap_or("");
            write!(f, "{}", self_str)
        }
    }
}