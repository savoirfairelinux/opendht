use libc::{c_char, c_void, in_port_t, size_t};

const HASH_LEN: usize = 20;

#[repr(C)]
pub struct InfoHash
{
    pub d: [u8; HASH_LEN],
}

#[repr(C)]
pub struct DhtRunner
{
    _opaque: [u8; 0]
}

#[repr(C)]
pub struct Value
{
    _opaque: [u8; 0]
}

#[repr(C)]
pub struct DataView
{
    pub data: *const u8,
    pub size: size_t
}


#[repr(C)]
pub struct OpToken
{
    _opaque: [u8; 0]
}


#[link(name = "opendht-c")]
extern {
    pub fn dht_infohash_print(h: *const InfoHash) -> *mut c_char;
    pub fn dht_infohash_random(h: *mut InfoHash);
    pub fn dht_infohash_get(h: *mut InfoHash, dat: *mut u8, dat_size: size_t);

    pub fn dht_value_get_data(data: *const Value) -> DataView;
    pub fn dht_value_unref(data: *mut Value);
    pub fn dht_value_new(data: *const u8, size: size_t) -> *mut Value;

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
                      cb_user_data: *mut c_void) -> *const OpToken;
    pub fn dht_runner_cancel_listen(dht: *mut DhtRunner, h: *const InfoHash, token: *const OpToken);
}