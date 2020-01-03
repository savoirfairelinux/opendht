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

#![allow(dead_code)]

use libc::c_void;
use std::ffi::CString;
use std::ptr;

pub use crate::ffi::*;
use std::net::SocketAddr;
use os_socketaddr::OsSocketAddr;

impl DhtRunnerConfig {

    pub fn new() -> Box<DhtRunnerConfig> {
        let mut config: Box<DhtRunnerConfig> = Box::new(DhtRunnerConfig {
            dht_config: DhtSecureConfig {
                node_config: DhtNodeConfig {
                    node_id: InfoHash::new(),
                    network: 0,
                    is_bootstrap: false,
                    maintain_storage: false,
                    persist_path: ptr::null(),
                },
                id: DhtIdentity {
                    privatekey: ptr::null_mut(),
                    certificate: ptr::null_mut(),
                },
            },
            threaded: false,
            proxy_server: ptr::null(),
            push_node_id: ptr::null(),
            push_token: ptr::null(),
            peer_discovery: false,
            peer_publish: false,
            server_ca: ptr::null_mut(),
            client_identity: DhtIdentity {
                privatekey: ptr::null_mut(),
                certificate: ptr::null_mut(),
            },
        });
        unsafe {
            dht_runner_config_default(&mut *config);
        }
        config
    }

    pub fn set_proxy_server(&mut self, proxy_server: &str) {
        self.proxy_server = CString::new(proxy_server).unwrap().as_ptr();
    }

    pub fn set_push_node_id(&mut self, push_node_id: &str) {
        self.push_node_id = CString::new(push_node_id).unwrap().as_ptr();
    }

    pub fn set_push_token(&mut self, push_token: &str) {
        self.push_token = CString::new(push_token).unwrap().as_ptr();
    }

    pub fn set_identity(&mut self, certificate: Box<DhtCertificate>, privatekey: Box<PrivateKey>) {
        self.dht_config.id.privatekey = Box::into_raw(privatekey);
        self.dht_config.id.certificate = Box::into_raw(certificate);
    }

}

impl DhtNodeConfig
{
    pub fn set_persist_path(&mut self, persist_path: &str) {
        self.persist_path = CString::new(persist_path).unwrap().as_ptr();
    }
}

struct GetHandler<'a>
{
    get_cb: &'a mut(dyn FnMut(Box<Value>) -> bool),
    done_cb: &'a mut(dyn FnMut(bool))
}

impl<'a> GetHandler<'a>
{
    fn get_cb(&mut self, v: Box<Value>) -> bool{
        (self.get_cb)(v)
    }

    fn done_cb(&mut self, ok: bool) {
        (self.done_cb)(ok)
    }
}

extern fn get_handler_cb(v: *mut Value, ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return true;
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
    cb: &'a mut(dyn FnMut(Box<Value>, bool) -> bool)
}

impl<'a> ListenHandler<'a>
{
    fn cb(&mut self, v: Box<Value>, expired: bool) -> bool {
        (self.cb)(v, expired)
    }
}

extern fn listen_handler(v: *mut Value, expired: bool, ptr: *mut c_void) -> bool {
    unsafe {
        let handler = ptr as *mut ListenHandler;
        (*handler).cb((*v).boxed(), expired)
    }
}

extern fn listen_handler_done(ptr: *mut c_void) {
    unsafe {
        Box::from_raw(ptr as *mut ListenHandler);
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

    pub fn run_config(&mut self, port: u16, config: Box<DhtRunnerConfig>) {
        unsafe {
            dht_runner_run_config(&mut *self, port, &*config)
        }
    }

    pub fn bootstrap(&mut self, host: &str, service: u16) {
        unsafe {
            dht_runner_bootstrap(&mut *self,
                CString::new(host).unwrap().as_ptr(),
                CString::new(service.to_string()).unwrap().as_ptr())
        }
    }

    pub fn node_id(&self) -> InfoHash {
        unsafe {
            dht_runner_get_node_id(&*self)
        }
    }

    pub fn id(&self) -> InfoHash {
        unsafe {
            dht_runner_get_id(&*self)
        }
    }

    pub fn get<'a>(&mut self, h: &InfoHash,
                get_cb: &'a mut(dyn FnMut(Box<Value>) -> bool),
                done_cb: &'a mut(dyn FnMut(bool))) {
        let handler = Box::new(GetHandler {
            get_cb,
            done_cb,
        });
        let handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            dht_runner_get(&mut *self, h, get_handler_cb, done_handler_cb, handler)
        }
    }

    pub fn put<'a>(&mut self, h: &InfoHash, v: Box<Value>,
                   done_cb: &'a mut(dyn FnMut(bool)), permanent: bool) {
        let handler = Box::new(PutHandler {
            done_cb,
        });
        let handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            dht_runner_put(&mut *self, h, &*v, put_handler_done, handler, permanent)
        }
    }

    pub fn put_signed<'a>(&mut self, h: &InfoHash, v: Box<Value>,
                                                 done_cb: &'a mut(dyn FnMut(bool)), permanent: bool) {
        let handler = Box::new(PutHandler {
            done_cb,
        });
        let handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            dht_runner_put_signed(&mut *self, h, &*v, put_handler_done, handler, permanent)
        }
    }

    pub fn put_encrypted<'a>(&mut self, h: &InfoHash, to: &InfoHash, v: Box<Value>,
                             done_cb: &'a mut(dyn FnMut(bool)), permanent: bool) {
        let handler = Box::new(PutHandler {
            done_cb,
        });
        let handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            dht_runner_put_encrypted(&mut *self, h, to, &*v, put_handler_done, handler, permanent)
        }
    }

    pub fn cancel_put<'a>(&mut self, h: &InfoHash, vid: u64) {
        unsafe {
            dht_runner_cancel_put(&mut *self, h, vid)
        }
    }

    pub fn listen<'a>(&mut self, h: &InfoHash,
                cb: &'a mut(dyn FnMut(Box<Value>, bool) -> bool)) -> Box<OpToken> {
        let handler = Box::new(ListenHandler {
            cb,
        });
        let handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            Box::from_raw(dht_runner_listen(&mut *self, h, listen_handler, listen_handler_done, handler))
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

    pub fn public_addresses(&self) -> Vec<SocketAddr> {
        let mut result = Vec::new();
        unsafe {
            let mut addresses = dht_runner_get_public_address(&*self);
            while !addresses.is_null() && !(*addresses).is_null() {
                let sock = (*(*addresses)).into_addr();
                if sock.is_some() {
                    result.push(sock.unwrap());
                }
                addresses = (addresses as usize + std::mem::size_of::<*mut OsSocketAddr>()) as *mut *mut OsSocketAddr;
            }
        }
        result
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