// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#![allow(dead_code)]

use libc::{c_char, c_int, c_uint, c_void, in_port_t, sa_family_t, size_t, sockaddr, socklen_t};

const HASH_LEN: usize = 20;
const PKID_LEN: usize = 32;

#[repr(C)]
pub struct DataView {
    pub data: *const u8,
    pub size: size_t,
}

#[repr(C)]
pub struct Value {
    _opaque: [u8; 0],
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

#[repr(C)]
pub struct Blob {
    _opaque: [u8; 0],
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

#[repr(C)]
#[derive(PartialEq)]
pub struct InfoHash {
    pub d: [u8; HASH_LEN],
}

#[repr(C)]
pub struct PkId {
    pub d: [u8; PKID_LEN],
}

#[repr(C)]
pub struct PublicKey {
    _opaque: [u8; 0],
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

#[repr(C)]
pub struct PrivateKey {
    _opaque: [u8; 0],
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

#[repr(C)]
pub struct OpToken {
    _opaque: [u8; 0],
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

#[repr(C)]
pub struct DhtRunner {
    _opaque: [u8; 0],
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

#[repr(C)]
pub struct DhtNodeConfig {
    pub node_id: InfoHash,
    pub network: u32,
    pub is_bootstrap: bool,
    pub maintain_storage: bool,
    pub persist_path: *const c_char,
}

#[repr(C)]
pub struct DhtCertificate {
    _opaque: [u8; 0],
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

#[repr(C)]
pub struct DhtIdentity {
    pub privatekey: *mut PrivateKey,
    pub certificate: *mut DhtCertificate,
}

#[repr(C)]
pub struct DhtSecureConfig {
    pub node_config: DhtNodeConfig,
    pub id: DhtIdentity,
}

#[repr(C)]
pub struct DhtRunnerConfig {
    pub dht_config: DhtSecureConfig,
    pub threaded: bool,
    pub proxy_server: *const c_char,
    pub push_node_id: *const c_char,
    pub push_token: *const c_char,
    pub push_topic: *const c_char,
    pub push_platform: *const c_char,
    pub proxy_user_agent: *const c_char,
    pub peer_discovery: bool,
    pub peer_publish: bool,
    pub server_ca: *mut DhtCertificate,
    pub client_identity: DhtIdentity,
    pub log: bool,
}

pub type CertificateCallback = extern "C" fn(*const DhtCertificate, *mut c_void);

#[repr(C)]
pub struct DhtRunnerContext {
    pub status_cb: Option<extern "C" fn(c_int, c_int, *mut c_void)>,
    pub certificate_store_cb:
        Option<extern "C" fn(*const PkId, CertificateCallback, *mut c_void, *mut c_void)>,
    pub released_cb: Option<extern "C" fn(*mut c_void)>,
    pub user_data: *mut c_void,
}

#[repr(C)]
pub struct QueryResult {
    pub fields: u32,
    pub id: u64,
    pub value_type: u16,
    pub seq: u16,
    pub owner: InfoHash,
    pub user_type: DataView,
}

#[repr(C)]
pub struct PushToken {
    _opaque: [u8; 0],
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

#[link(name = "opendht-c")]
extern "C" {
    // dht::Value
    pub fn dht_value_new(data: *const u8, size: size_t) -> *mut Value;
    pub fn dht_value_with_id_new(data: *const u8, size: size_t, id: u64) -> *mut Value;
    pub fn dht_value_ref(data: *const Value) -> *mut Value;
    pub fn dht_value_copy(data: *const Value) -> *mut Value;
    pub fn dht_value_unref(data: *mut Value);
    pub fn dht_value_get_data(data: *const Value) -> DataView;
    pub fn dht_value_get_id(data: *const Value) -> u64;
    pub fn dht_value_get_owner(data: *const Value) -> *mut PublicKey;
    pub fn dht_value_get_recipient(data: *const Value) -> InfoHash;
    pub fn dht_value_get_user_type(data: *const Value) -> *const c_char;
    pub fn dht_value_set_user_type(data: *mut Value, user_type: *const c_char);
    pub fn dht_value_get_type(data: *const Value) -> u16;
    pub fn dht_value_set_type(data: *mut Value, value_type: u16);
    pub fn dht_value_get_seq(data: *const Value) -> u16;
    pub fn dht_value_set_seq(data: *mut Value, seq: u16);
    pub fn dht_value_get_priority(data: *const Value) -> c_uint;
    pub fn dht_value_set_priority(data: *mut Value, priority: c_uint);
    pub fn dht_value_get_push_type(data: *const Value) -> *const c_char;
    pub fn dht_value_set_push_type(data: *mut Value, push_type: *const c_char);

    // dht::Blob
    pub fn dht_blob_get_data(data: *const Blob) -> DataView;
    pub fn dht_blob_delete(data: *mut Blob);

    // dht::InfoHash
    pub fn dht_infohash_print(h: *const InfoHash) -> *const c_char;
    pub fn dht_infohash_random(h: *mut InfoHash);
    pub fn dht_infohash_get(h: *mut InfoHash, dat: *const u8, dat_size: size_t);
    pub fn dht_infohash_from_hex(h: *mut InfoHash, dat: *const c_char);
    pub fn dht_infohash_from_hex_null(h: *mut InfoHash, dat: *const c_char);
    pub fn dht_infohash_is_zero(j: *const InfoHash) -> bool;

    // dht::PkId
    pub fn dht_pkid_print(h: *const PkId) -> *const c_char;

    // dht::crypto::PublicKey
    pub fn dht_publickey_import(dat: *const u8, dat_size: size_t) -> *mut PublicKey;
    pub fn dht_publickey_delete(pk: *mut PublicKey);
    pub fn dht_publickey_export_blob(pk: *const PublicKey) -> *mut Blob;
    pub fn dht_publickey_unpack(pk: *mut PublicKey, data: *const u8, size: size_t) -> c_int;
    pub fn dht_publickey_get_id(pk: *const PublicKey) -> InfoHash;
    pub fn dht_publickey_get_long_id(pk: *const PublicKey) -> PkId;
    pub fn dht_publickey_check_signature(
        pk: *const PublicKey,
        data: *const c_char,
        data_size: size_t,
        signature: *const c_char,
        signature_size: size_t,
    ) -> bool;
    pub fn dht_publickey_encrypt(
        pk: *const PublicKey,
        data: *const c_char,
        data_size: size_t,
    ) -> *mut Blob;

    // dht::crypto::PrivateKey
    pub fn dht_privatekey_generate(key_length_bits: c_uint) -> *mut PrivateKey;
    pub fn dht_privatekey_generate_ec() -> *mut PrivateKey;
    pub fn dht_privatekey_import(
        dat: *const u8,
        data_size: size_t,
        password: *const c_char,
    ) -> *mut PrivateKey;
    pub fn dht_privatekey_get_publickey(pk: *const PrivateKey) -> *mut PublicKey;
    pub fn dht_privatekey_export_blob(pk: *const PrivateKey, password: *const c_char) -> *mut Blob;
    pub fn dht_privatekey_sign(pk: *const PrivateKey, data: *const u8, size: size_t) -> *mut Blob;
    pub fn dht_privatekey_decrypt(
        pk: *const PrivateKey,
        data: *const c_char,
        size: size_t,
    ) -> *mut Blob;
    pub fn dht_privatekey_delete(pk: *mut PrivateKey);

    // dht::crypto::Certificate
    pub fn dht_certificate_import(dat: *const u8, dat_size: size_t) -> *mut DhtCertificate;
    pub fn dht_certificate_export(cert: *const DhtCertificate) -> *mut Blob;
    pub fn dht_certificate_ref(cert: *const DhtCertificate) -> *mut DhtCertificate;
    pub fn dht_certificate_get_id(cert: *const DhtCertificate) -> InfoHash;
    pub fn dht_certificate_get_long_id(cert: *const DhtCertificate) -> PkId;
    pub fn dht_certificate_get_publickey(cert: *const DhtCertificate) -> *mut PublicKey;
    pub fn dht_certificate_delete(cert: *mut DhtCertificate);

    pub fn dht_identity_generate(common_name: *const c_char, ca: *const DhtIdentity)
        -> DhtIdentity;
    pub fn dht_identity_generate_ec(
        common_name: *const c_char,
        ca: *const DhtIdentity,
    ) -> DhtIdentity;
    pub fn dht_identity_delete(ca: *mut DhtIdentity);

    // dht::OpToken
    pub fn dht_op_token_delete(token: *mut OpToken);

    // dht::DhtRunner
    pub fn dht_runner_config_default(config: *mut DhtRunnerConfig);
    pub fn dht_runner_new() -> *mut DhtRunner;
    pub fn dht_runner_get_id(dht: *const DhtRunner) -> InfoHash;
    pub fn dht_runner_get_node_id(dht: *const DhtRunner) -> InfoHash;
    pub fn dht_runner_delete(dht: *mut DhtRunner);
    pub fn dht_runner_run(dht: *mut DhtRunner, port: in_port_t) -> c_int;
    pub fn dht_runner_run_config(
        dht: *mut DhtRunner,
        port: in_port_t,
        config: *const DhtRunnerConfig,
    ) -> c_int;
    pub fn dht_runner_run_bind(
        dht: *mut DhtRunner,
        ipv4: *const c_char,
        ipv6: *const c_char,
        port: in_port_t,
        config: *const DhtRunnerConfig,
        context: *const DhtRunnerContext,
    ) -> c_int;
    pub fn dht_runner_connectivity_changed(dht: *mut DhtRunner) -> c_int;
    pub fn dht_runner_register_type(
        dht: *mut DhtRunner,
        id: u16,
        name: *const c_char,
        expiration_seconds: u64,
        insecure: bool,
    ) -> c_int;
    pub fn dht_runner_get_publickey(dht: *const DhtRunner) -> *mut PublicKey;
    pub fn dht_runner_register_certificate(
        dht: *mut DhtRunner,
        cert: *const DhtCertificate,
    ) -> c_int;
    pub fn dht_runner_find_certificate(
        dht: *mut DhtRunner,
        id: *const PkId,
        callback: CertificateCallback,
        released: extern "C" fn(*mut c_void),
        data: *mut c_void,
    );
    pub fn dht_runner_bootstrap(dht: *mut DhtRunner, host: *const c_char, service: *const c_char);
    pub fn dht_runner_get(
        dht: *mut DhtRunner,
        h: *const InfoHash,
        get_cb: extern "C" fn(*const Value, *mut c_void) -> bool,
        done_cb: extern "C" fn(bool, *mut c_void),
        cb_user_data: *mut c_void,
    );
    pub fn dht_runner_get_filtered(
        dht: *mut DhtRunner,
        h: *const InfoHash,
        filter: *const c_char,
        callback: extern "C" fn(*const Value, *mut c_void) -> bool,
        done: extern "C" fn(bool, *mut c_void),
        data: *mut c_void,
    );
    pub fn dht_runner_query(
        dht: *mut DhtRunner,
        h: *const InfoHash,
        query: *const c_char,
        callback: extern "C" fn(*const QueryResult, *mut c_void) -> bool,
        done: extern "C" fn(bool, *mut c_void),
        data: *mut c_void,
    );
    pub fn dht_runner_put(
        dht: *mut DhtRunner,
        h: *const InfoHash,
        v: *const Value,
        done_cb: extern "C" fn(bool, *mut c_void),
        cb_user_data: *mut c_void,
        permanent: bool,
    );
    pub fn dht_runner_put_signed(
        dht: *mut DhtRunner,
        h: *const InfoHash,
        v: *const Value,
        done_cb: extern "C" fn(bool, *mut c_void),
        cb_user_data: *mut c_void,
        permanent: bool,
    );
    pub fn dht_runner_put_encrypted(
        dht: *mut DhtRunner,
        h: *const InfoHash,
        to: *const PkId,
        v: *const Value,
        done_cb: extern "C" fn(bool, *mut c_void),
        cb_user_data: *mut c_void,
        permanent: bool,
    );
    pub fn dht_runner_cancel_put(dht: *mut DhtRunner, h: *const InfoHash, vid: u64);
    pub fn dht_runner_listen(
        dht: *mut DhtRunner,
        h: *const InfoHash,
        cb: extern "C" fn(*const Value, bool, *mut c_void) -> bool,
        done_cb: extern "C" fn(*mut c_void),
        cb_user_data: *mut c_void,
    ) -> *mut OpToken;
    pub fn dht_runner_listen_filtered(
        dht: *mut DhtRunner,
        h: *const InfoHash,
        filter: *const c_char,
        callback: extern "C" fn(*const Value, bool, *mut c_void) -> bool,
        released: extern "C" fn(*mut c_void),
        data: *mut c_void,
    ) -> *mut OpToken;
    pub fn dht_runner_cancel_listen(dht: *mut DhtRunner, h: *const InfoHash, token: *mut OpToken);
    pub fn dht_runner_shutdown(
        dht: *mut DhtRunner,
        done_cb: extern "C" fn(*mut c_void),
        cb_user_data: *mut c_void,
    );
    pub fn dht_runner_get_public_address(dht: *const DhtRunner) -> *mut *mut sockaddr;
    pub fn dht_sockaddr_array_delete(addresses: *mut *mut sockaddr);
    pub fn dht_runner_loop(dht: *mut DhtRunner) -> c_int;
    pub fn dht_runner_join(dht: *mut DhtRunner) -> c_int;
    pub fn dht_runner_is_running(dht: *const DhtRunner) -> bool;
    pub fn dht_runner_get_bound_port(dht: *const DhtRunner, family: sa_family_t) -> in_port_t;
    pub fn dht_runner_ping(
        dht: *mut DhtRunner,
        addr: *mut sockaddr,
        len: socklen_t,
        callback: extern "C" fn(bool, *mut c_void),
        data: *mut c_void,
    );
    pub fn dht_runner_set_push_notification_token(
        dht: *mut DhtRunner,
        value: *const c_char,
    ) -> c_int;
    pub fn dht_runner_set_push_notification_topic(
        dht: *mut DhtRunner,
        value: *const c_char,
    ) -> c_int;
    pub fn dht_runner_set_push_notification_platform(
        dht: *mut DhtRunner,
        value: *const c_char,
    ) -> c_int;
    pub fn dht_runner_push_notification_received(
        dht: *mut DhtRunner,
        keys: *const *const c_char,
        values: *const *const c_char,
        count: size_t,
    ) -> *mut PushToken;
    pub fn dht_push_token_poll(token: *mut PushToken, result: *mut c_int) -> c_int;
    pub fn dht_push_token_delete(token: *mut PushToken);
}
