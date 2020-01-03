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

pub use crate::ffi::*;
use std::ffi::CString;
use std::io;
use std::io::prelude::*;
use std::fs::File;
use std::ptr;

impl PublicKey {
    pub fn new(data: &str) -> Box<PublicKey> {
        unsafe {
            Box::from_raw(dht_publickey_import(data.as_ptr(), data.len()))
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

    pub fn import(file: &str, password: &str) -> io::Result<Box<PrivateKey>> {
        let mut f = File::open(file)?;
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer)?;
        Ok(PrivateKey::from_bytes(&buffer, password))
    }

    pub fn from_bytes(buffer: &Vec<u8>, password: &str) -> Box<PrivateKey> {
        unsafe {
            Box::from_raw(dht_privatekey_import((&*buffer).as_ptr(), buffer.len(),
                password.as_ptr() as *const i8))
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

impl DhtCertificate {
    pub fn import(file: &str) -> io::Result<Box<DhtCertificate>> {
        let mut f = File::open(file)?;
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer)?;
        Ok(DhtCertificate::from_bytes(&buffer))
    }

    pub fn from_bytes(buffer: &Vec<u8>) -> Box<DhtCertificate> {
        unsafe {
            Box::from_raw(dht_certificate_import((&*buffer).as_ptr(), buffer.len()))
        }
    }

    pub fn from_slice(buffer: &str) -> Box<DhtCertificate> {
        unsafe {
            Box::from_raw(dht_certificate_import((&*buffer).as_ptr(), buffer.len()))
        }
    }

    pub fn id(&self) -> InfoHash {
        unsafe {
            dht_certificate_get_id(&*self)
        }
    }

    pub fn long_id(&self) -> PkId {
        unsafe {
            dht_certificate_get_long_id(&*self)
        }
    }

    pub fn publickey(&self) -> Box<PublicKey> {
        unsafe {
            Box::from_raw(dht_certificate_get_publickey(&*self))
        }
    }
}

impl Drop for DhtCertificate {
    fn drop(&mut self) {
        unsafe {
            dht_certificate_delete(&mut *self)
        }
    }
}

impl DhtIdentity {
    pub fn new(common_name: &str) -> DhtIdentity {
        unsafe {
            DhtIdentity::generate(common_name, Box::from_raw(ptr::null_mut()))
        }
    }

    pub fn generate(common_name: &str, ca: Box<DhtIdentity>) -> DhtIdentity {
        let common_name = CString::new(common_name).unwrap();
        unsafe {
            dht_identity_generate(common_name.as_ptr(), &*ca)
        }
    }
}

impl Drop for DhtIdentity {
    fn drop(&mut self) {
        unsafe {
            dht_identity_delete(&mut *self)
        }
    }
}