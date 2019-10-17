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
use std::ffi::CString;

impl PublicKey {
    pub fn new() -> Box<PublicKey> {
        unsafe {
            Box::from_raw(dht_publickey_new())
        }
    }

    pub fn unpack(&mut self, data: Vec<u8>) -> i32 {
        unsafe {
            dht_publickey_unpack(&mut *self, data.as_ptr(), data.len())
        }
    }

    pub fn pack(&mut self, data: &str) -> i32 {
        let data = CString::new(data).unwrap();
        unsafe {
            dht_publickey_pack(&mut *self,
                data.as_ptr(),
                data.as_bytes().len())
        }
    }

    pub fn id(&self) -> InfoHash {
        unsafe {
            dht_publickey_get_id(self)
        }
    }

    pub fn long_id(&self) -> PkId {
        unsafe {
            dht_publickey_get_long_id(self)
        }
    }

    pub fn check_signature(&self, data: &str, signature: &str) -> bool {
        let data = CString::new(data).unwrap();
        let signature = CString::new(signature).unwrap();
        unsafe {
            dht_publickey_check_signature(self,
                data.as_ptr(), data.as_bytes().len(),
                signature.as_ptr(), signature.as_bytes().len())
        }
    }

    pub fn encrypt(&self, data: &str) -> Box<Blob> {
        let data = CString::new(data).unwrap();
        unsafe {
            Box::from_raw(dht_publickey_encrypt(self,
                data.as_ptr(), data.as_bytes().len()))
        }
    }
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe {
            dht_publickey_delete(&mut *self)
        }
    }
}

impl PrivateKey {
    pub fn new(key_length_bits: u32) -> Box<PrivateKey> {
        unsafe {
            Box::from_raw(dht_privatekey_generate(key_length_bits))
        }
    }

    pub fn import(data: &str, password: &str) -> Box<PrivateKey> {
        let password = CString::new(password).unwrap();
        unsafe {
            Box::from_raw(dht_privatekey_import(data.as_ptr(),
                data.as_bytes().len(), password.as_ptr()))
        }
    }

    pub fn public_key(&self) -> Box<PublicKey> {
        unsafe {
            Box::from_raw(dht_privatekey_get_publickey(self))
        }
    }

}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe {
            dht_privatekey_delete(&mut *self)
        }
    }
}