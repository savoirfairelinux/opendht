/*
 *  Copyright (C) 2019 Savoir-faire Linux Inc.
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
use std::fmt;
use std::str;
use std::slice;

pub use crate::ffi::{DataView, Value};

impl Value {
    pub fn new(data: &str) -> Box<Value> {
        unsafe {
            Box::from_raw(dht_value_new(data.as_bytes().as_ptr(),
                data.as_bytes().len()))
        }
    }

    fn dataview(&self) -> DataView {
        unsafe {
            dht_value_get_data(self)
        }
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        unsafe {
            dht_value_unref(&mut *self)
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let dataview = self.dataview();
            let slice = slice::from_raw_parts(dataview.data, dataview.size);
            write!(f, "{}", str::from_utf8(slice).unwrap_or(""))
        }
    }
}
