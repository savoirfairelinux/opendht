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

pub use crate::ffi::{ DhtRunner, OpToken, Value };

struct GetHandler<'a>
{
    get_cb: &'a mut(dyn FnMut(Box<Value>)),
    done_cb: &'a mut(dyn FnMut(bool))
}

impl<'a> GetHandler<'a>
{
    fn get_cb(&mut self, v: Box<Value>) {
        (self.get_cb)(v)
    }

    fn done_cb(&mut self, ok: bool) {
        (self.done_cb)(ok)
    }
}

extern fn get_handler_cb(v: *mut Value, ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let handler = ptr as *mut GetHandler;
        (*handler).get_cb((*v).boxed())
    }
}

extern fn done_handler_cb(ok: bool, ptr: *mut c_void) {
    unsafe {
        let handler = Box::from_raw(ptr as *mut GetHandler);
        (*handler.done_cb)(ok)
    }
}

struct PutHandler<'a>
{
    done_cb: &'a mut(dyn FnMut(bool))
}

impl<'a> PutHandler<'a>
{
    fn done_cb(&mut self, ok: bool) {
        (self.done_cb)(ok)
    }
}

extern fn put_handler_done(ok: bool, ptr: *mut c_void) {
    unsafe {
        let handler = Box::from_raw(ptr as *mut PutHandler);
        (*handler.done_cb)(ok)
    }
}

struct ListenHandler<'a>
{
    cb: &'a mut(dyn FnMut(Box<Value>, bool))
}

impl<'a> ListenHandler<'a>
{
    fn cb(&mut self, v: Box<Value>, expired: bool) {
        (self.cb)(v, expired)
    }
}

extern fn listen_handler(v: *mut Value, expired: bool, ptr: *mut c_void) {
    unsafe {
        let handler = ptr as *mut ListenHandler;
        (*handler).cb((*v).boxed(), expired)
    }
}

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

    pub fn get<'a>(&mut self, h: &InfoHash,
                get_cb: &'a mut(dyn FnMut(Box<Value>)),
                done_cb: &'a mut(dyn FnMut(bool))) {
        let mut handler = Box::new(GetHandler {
            get_cb,
            done_cb,
        });
        let mut handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            dht_runner_get(&mut *self, h, get_handler_cb, done_handler_cb, handler)
        }
    }

    pub fn put<'a>(&mut self, h: &InfoHash, v: Box<Value>,
                done_cb: &'a mut(dyn FnMut(bool))) {
        let mut handler = Box::new(PutHandler {
            done_cb,
        });
        let mut handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            dht_runner_put(&mut *self, h, &*v, put_handler_done, handler)
        }
    }

    pub fn listen<'a>(&mut self, h: &InfoHash,
                cb: &'a mut(dyn FnMut(Box<Value>, bool))) -> Box<OpToken> {
        let mut handler = Box::new(ListenHandler {
            cb,
        });
        let mut handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            Box::from_raw(dht_runner_listen(&mut *self, h, listen_handler, handler))
        }
    }

    pub fn cancel_listen(&mut self, h: &InfoHash, token: Box<OpToken>) {
        // TODO: handler is not dropped!
        // NOTE: MEMORY LEAK!
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