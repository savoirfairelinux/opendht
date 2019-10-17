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
use libc::c_void;
use std::ffi::CString;
use std::fmt;

pub use crate::ffi::{ DhtRunner, OpToken, Value };

impl DhtRunner {
    pub fn new() -> Box<DhtRunner> {
        unsafe {
            Box::from_raw(dht_runner_new())
        }
    }

    pub fn run(&mut self, port: u16) {
        unsafe {
            dht_runner_run(&mut *self, port)
        }
    }

    pub fn bootstrap(&mut self, host: &str, service: u16) {
        unsafe {
            dht_runner_bootstrap(&mut *self,
                CString::new(host).unwrap().as_ptr(),
                CString::new(service.to_string()).unwrap().as_ptr())
        }
    }

    pub fn get(&mut self, h: &InfoHash,
               get_cb: extern fn(*mut Value, *mut c_void),
               done_cb: extern fn(bool, *mut c_void),
               cb_user_data: *mut c_void) {

        unsafe {
            dht_runner_get(&mut *self, h, get_cb, done_cb, cb_user_data)
        }
    }

    pub fn put(&mut self, h: &InfoHash, v: Box<Value>,
               done_cb: extern fn(bool, *mut c_void),
               cb_user_data: *mut c_void) {

        unsafe {
            dht_runner_put(&mut *self, h, &*v, done_cb, cb_user_data)
        }
    }

    pub fn listen(&mut self, h: &InfoHash,
                  cb: extern fn(*mut Value, bool, *mut c_void),
                  cb_user_data: *mut c_void) -> Box<OpToken> {
        unsafe {
            Box::from_raw(dht_runner_listen(&mut *self, h, cb, cb_user_data))
        }
    }

    pub fn cancel_listen(&mut self, h: &InfoHash, token: Box<OpToken>) {

        unsafe {
            dht_runner_cancel_listen(&mut *self, h, &*token)
        }
    }

    pub fn shutdown(&mut self,
                    done_cb: extern fn(bool, *mut c_void),
                    cb_user_data: *mut c_void)
    {
        unsafe {
            dht_runner_shutdown(&mut *self, done_cb, cb_user_data)
        }
    }
}

impl Drop for DhtRunner {
    fn drop(&mut self) {
        unsafe {
            dht_runner_delete(&mut *self)
        }
    }
}

impl Drop for OpToken {
    fn drop(&mut self) {
        unsafe {
            dht_op_token_delete(&mut *self)
        }
    }
}