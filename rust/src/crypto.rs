// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

use crate::{ffi, Blob, InfoHash, PkId};
use std::ffi::CString;
use std::fs;
use std::io;
use std::ptr;

native_handle!(PublicKey, dht_publickey_delete);
native_handle!(PrivateKey, dht_privatekey_delete);
native_handle!(DhtCertificate, dht_certificate_delete);

impl PublicKey {
    pub fn new(data: impl AsRef<[u8]>) -> io::Result<Box<PublicKey>> {
        let data = data.as_ref();
        unsafe { Self::from_raw(ffi::dht_publickey_import(data.as_ptr(), data.len())) }
    }

    pub fn unpack(&mut self, data: impl AsRef<[u8]>) -> io::Result<()> {
        let data = data.as_ref();
        let result = unsafe { ffi::dht_publickey_unpack(self.as_ptr(), data.as_ptr(), data.len()) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::other("invalid public key"))
        }
    }

    pub fn pack(&self) -> io::Result<Vec<u8>> {
        unsafe { Ok(Blob::from_raw(ffi::dht_publickey_export_blob(self.as_ptr()))?.as_bytes()) }
    }

    pub fn id(&self) -> InfoHash {
        unsafe { ffi::dht_publickey_get_id(self.as_ptr()) }
    }

    pub fn long_id(&self) -> PkId {
        unsafe { ffi::dht_publickey_get_long_id(self.as_ptr()) }
    }

    pub fn check_signature(&self, data: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> bool {
        let data = data.as_ref();
        let signature = signature.as_ref();
        unsafe {
            ffi::dht_publickey_check_signature(
                self.as_ptr(),
                data.as_ptr().cast(),
                data.len(),
                signature.as_ptr().cast(),
                signature.len(),
            )
        }
    }

    pub fn encrypt(&self, data: impl AsRef<[u8]>) -> io::Result<Box<Blob>> {
        let data = data.as_ref();
        unsafe {
            Blob::from_raw(ffi::dht_publickey_encrypt(
                self.as_ptr(),
                data.as_ptr().cast(),
                data.len(),
            ))
        }
    }
}

impl PrivateKey {
    pub fn new(key_length_bits: u32) -> io::Result<Box<PrivateKey>> {
        unsafe { Self::from_raw(ffi::dht_privatekey_generate(key_length_bits)) }
    }

    pub fn new_ec() -> io::Result<Box<PrivateKey>> {
        unsafe { Self::from_raw(ffi::dht_privatekey_generate_ec()) }
    }

    pub fn import(file: &str, password: &str) -> io::Result<Box<PrivateKey>> {
        Self::from_bytes(&fs::read(file)?, password)
    }

    pub fn from_bytes(buffer: &[u8], password: &str) -> io::Result<Box<PrivateKey>> {
        let password = CString::new(password)?;
        unsafe {
            Self::from_raw(ffi::dht_privatekey_import(
                buffer.as_ptr(),
                buffer.len(),
                password.as_ptr(),
            ))
        }
    }

    pub fn public_key(&self) -> Box<PublicKey> {
        unsafe {
            PublicKey::from_raw(ffi::dht_privatekey_get_publickey(self.as_ptr()))
                .expect("private key has a public key")
        }
    }

    pub fn serialize(&self, password: &str) -> io::Result<Vec<u8>> {
        let password = CString::new(password)?;
        unsafe {
            Ok(Blob::from_raw(ffi::dht_privatekey_export_blob(
                self.as_ptr(),
                password.as_ptr(),
            ))?
            .as_bytes())
        }
    }

    pub fn sign(&self, data: impl AsRef<[u8]>) -> io::Result<Vec<u8>> {
        let data = data.as_ref();
        unsafe {
            Ok(Blob::from_raw(ffi::dht_privatekey_sign(
                self.as_ptr(),
                data.as_ptr(),
                data.len(),
            ))?
            .as_bytes())
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> io::Result<Box<Blob>> {
        unsafe {
            Blob::from_raw(ffi::dht_privatekey_decrypt(
                self.as_ptr(),
                data.as_ptr().cast(),
                data.len(),
            ))
        }
    }
}

impl DhtCertificate {
    pub fn import(file: &str) -> io::Result<Box<DhtCertificate>> {
        Self::from_bytes(&fs::read(file)?)
    }

    pub fn from_bytes(buffer: &[u8]) -> io::Result<Box<DhtCertificate>> {
        unsafe { Self::from_raw(ffi::dht_certificate_import(buffer.as_ptr(), buffer.len())) }
    }

    pub fn from_slice(buffer: &str) -> io::Result<Box<DhtCertificate>> {
        Self::from_bytes(buffer.as_bytes())
    }

    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        unsafe { Ok(Blob::from_raw(ffi::dht_certificate_export(self.as_ptr()))?.as_bytes()) }
    }

    pub fn id(&self) -> InfoHash {
        unsafe { ffi::dht_certificate_get_id(self.as_ptr()) }
    }

    pub fn long_id(&self) -> PkId {
        unsafe { ffi::dht_certificate_get_long_id(self.as_ptr()) }
    }

    pub fn publickey(&self) -> Box<PublicKey> {
        unsafe {
            PublicKey::from_raw(ffi::dht_certificate_get_publickey(self.as_ptr()))
                .expect("certificate has a public key")
        }
    }
}

pub struct DhtIdentity {
    pub privatekey: Box<PrivateKey>,
    pub certificate: Box<DhtCertificate>,
}

impl DhtIdentity {
    pub fn new(common_name: &str) -> io::Result<Self> {
        Self::generate_inner(common_name, None, false)
    }

    pub fn new_ec(common_name: &str) -> io::Result<Self> {
        Self::generate_inner(common_name, None, true)
    }

    pub fn generate(common_name: &str, ca: &DhtIdentity) -> io::Result<Self> {
        Self::generate_inner(common_name, Some(ca), false)
    }

    pub(crate) fn raw(&self) -> ffi::DhtIdentity {
        ffi::DhtIdentity {
            privatekey: self.privatekey.as_ptr(),
            certificate: self.certificate.as_ptr(),
        }
    }

    fn generate_inner(common_name: &str, ca: Option<&Self>, ec: bool) -> io::Result<Self> {
        let name = CString::new(common_name)?;
        let ca = ca.map(Self::raw);
        let ca_ptr = ca
            .as_ref()
            .map_or(ptr::null(), |identity| identity as *const _);
        unsafe {
            let mut raw = if ec {
                ffi::dht_identity_generate_ec(name.as_ptr(), ca_ptr)
            } else {
                ffi::dht_identity_generate(name.as_ptr(), ca_ptr)
            };
            if raw.privatekey.is_null() || raw.certificate.is_null() {
                ffi::dht_identity_delete(&mut raw);
                return Err(io::Error::other("identity generation failed"));
            }
            Ok(Self {
                privatekey: PrivateKey::from_raw(raw.privatekey)?,
                certificate: DhtCertificate::from_raw(raw.certificate)?,
            })
        }
    }
}
