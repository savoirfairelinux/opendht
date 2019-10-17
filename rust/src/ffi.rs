use libc::{c_char, c_int, c_uint, c_void, in_port_t, size_t};

const HASH_LEN: usize = 20;
const PKID_LEN: usize = 32;

#[repr(C)]
pub struct DataView
{
    pub data: *const u8,
    pub size: size_t
}

#[repr(C)]
pub struct Value
{
    _opaque: [u8; 0]
}

#[repr(C)]
pub struct Blob
{
    _opaque: [u8; 0]
}

#[repr(C)]
pub struct InfoHash
{
    pub d: [u8; HASH_LEN],
}

#[repr(C)]
pub struct PkId
{
    pub d: [u8; PKID_LEN],
}

#[repr(C)]
pub struct PublicKey
{
    _opaque: [u8; 0]
}

#[repr(C)]
pub struct PrivateKey
{
    _opaque: [u8; 0]
}

#[repr(C)]
pub struct OpToken
{
    _opaque: [u8; 0]
}

#[repr(C)]
pub struct DhtRunner
{
    _opaque: [u8; 0]
}


#[link(name = "opendht-c")]
extern {
    // dht::Value
    pub fn dht_value_get_data(data: *const Value) -> DataView;
    pub fn dht_value_new(data: *const u8, size: size_t) -> *mut Value;
    pub fn dht_value_ref(data: *const Value) -> *mut Value;
    pub fn dht_value_unref(data: *mut Value);

    // dht::Blob
    pub fn dht_blob_get_data(data: *const Blob) -> DataView;
    pub fn dht_blob_delete(data: *mut Blob);

    // dht::InfoHash
    pub fn dht_infohash_print(h: *const InfoHash) -> *const c_char;
    pub fn dht_infohash_random(h: *mut InfoHash);
    pub fn dht_infohash_get(h: *mut InfoHash, dat: *mut u8, dat_size: size_t);
    pub fn dht_infohash_is_zero(j: *const InfoHash) -> bool;

    // dht::PkId
    pub fn dht_pkid_print(h: *const PkId) -> *const c_char;

    // dht::crypto::PublicKey
    pub fn dht_publickey_new() -> *mut PublicKey;
    pub fn dht_publickey_delete(pk: *mut PublicKey);
    pub fn dht_publickey_unpack(pk: *mut PublicKey, dat: *const u8, dat_size: size_t) -> c_int;
    pub fn dht_publickey_pack(pk: *mut PublicKey, out: *const c_char, out_size: size_t) -> c_int;
    pub fn dht_publickey_get_id(pk: *const PublicKey) -> InfoHash;
    pub fn dht_publickey_get_long_id(pk: *const PublicKey) -> PkId;
    pub fn dht_publickey_check_signature(pk: *const PublicKey, data: *const c_char, data_size: size_t, signature: *const c_char, signature_size: size_t) -> bool;
    pub fn dht_publickey_encrypt(pk: *const PublicKey, data: *const c_char, data_size: size_t) -> *mut Blob;

    // dht::crypto::PrivateKey
    pub fn dht_privatekey_generate(key_length_bits: c_uint) -> *mut PrivateKey;
    pub fn dht_privatekey_import(dat: *const u8, data_size: size_t, password: *const c_char) -> *mut PrivateKey;
    pub fn dht_privatekey_get_publickey(pk: *const PrivateKey) -> *mut PublicKey;
    pub fn dht_privatekey_delete(pk: *mut PrivateKey);

    // dht::OpToken
    pub fn dht_op_token_delete(token: *mut OpToken);

    // dht::DhtRunner
    pub fn dht_runner_new() -> *mut DhtRunner;
    pub fn dht_runner_delete(dht: *mut DhtRunner);
    pub fn dht_runner_run(dht: *mut DhtRunner, port: in_port_t);
    pub fn dht_runner_bootstrap(dht: *mut DhtRunner, host: *const c_char, service: *const c_char);
    pub fn dht_runner_get(dht: *mut DhtRunner, h: *const InfoHash,
                      get_cb: extern fn(*mut Value, *mut c_void),
                      done_cb: extern fn(bool, *mut c_void),
                      cb_user_data: *mut c_void);
    pub fn dht_runner_put(dht: *mut DhtRunner, h: *const InfoHash, v: *const Value,
                      done_cb: extern fn(bool, *mut c_void),
                      cb_user_data: *mut c_void);
    pub fn dht_runner_listen(dht: *mut DhtRunner, h: *const InfoHash,
                      cb: extern fn(*mut Value, bool, *mut c_void),
                      cb_user_data: *mut c_void) -> *mut OpToken;
    pub fn dht_runner_cancel_listen(dht: *mut DhtRunner, h: *const InfoHash,
                      token: *const OpToken);
    pub fn dht_runner_shutdown(dht: *mut DhtRunner, done_cb: extern fn(bool, *mut c_void),
                      cb_user_data: *mut c_void);
}