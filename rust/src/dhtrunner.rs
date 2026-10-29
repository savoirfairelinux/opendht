// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

use libc::c_void;
use std::ffi::CString;
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::crypto::{DhtCertificate, DhtIdentity, PrivateKey, PublicKey};
use crate::{ffi, InfoHash, PkId, Value};
use os_socketaddr::OsSocketAddr;
use std::net::SocketAddr;
use std::sync::Mutex;

native_handle!(DhtRunner, dht_runner_delete);
native_handle!(OpToken, dht_op_token_delete);
native_handle!(PushToken, dht_push_token_delete);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    Disconnected,
    Connecting,
    Connected,
}

impl NodeStatus {
    fn from_raw(value: i32) -> Self {
        match value {
            1 => Self::Connecting,
            2 => Self::Connected,
            _ => Self::Disconnected,
        }
    }
}

pub struct QueryResult {
    pub id: Option<u64>,
    pub value_type: Option<u16>,
    pub seq: Option<u16>,
    pub owner: Option<InfoHash>,
    pub user_type: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushNotificationResult {
    PutRefresh,
    ListenRefresh,
    Values,
    ValuesExpired,
    IgnoredWrongSession,
    IgnoredNoOp,
    IgnoredStopped,
    IgnoredDisabled,
    Error,
}

pub struct PushNotification {
    token: Box<PushToken>,
    result: Option<PushNotificationResult>,
}

impl PushNotification {
    pub fn poll(&mut self) -> io::Result<Option<PushNotificationResult>> {
        if self.result.is_some() {
            return Ok(self.result);
        }
        let mut outcome = 0;
        let code = unsafe { ffi::dht_push_token_poll(self.token.as_ptr(), &mut outcome) };
        if code == libc::EAGAIN {
            return Ok(None);
        }
        result(code)?;
        self.result = Some(match outcome {
            0 => PushNotificationResult::PutRefresh,
            1 => PushNotificationResult::ListenRefresh,
            2 => PushNotificationResult::Values,
            3 => PushNotificationResult::ValuesExpired,
            128 => PushNotificationResult::IgnoredWrongSession,
            129 => PushNotificationResult::IgnoredNoOp,
            130 => PushNotificationResult::IgnoredStopped,
            131 => PushNotificationResult::IgnoredDisabled,
            _ => PushNotificationResult::Error,
        });
        Ok(self.result)
    }
}

type StatusCallback = Box<dyn FnMut(NodeStatus, NodeStatus) + Send>;
type CertificateStore = Box<dyn FnMut(&PkId) -> Vec<Box<DhtCertificate>> + Send>;

struct ContextCallbacks {
    status: Option<StatusCallback>,
    store: Option<CertificateStore>,
}

pub struct DhtNodeConfig {
    pub node_id: InfoHash,
    pub network: u32,
    pub is_bootstrap: bool,
    pub maintain_storage: bool,
    persist_path: Option<CString>,
}

pub struct DhtSecureConfig {
    pub node_config: DhtNodeConfig,
    pub id: Option<DhtIdentity>,
}

pub struct DhtRunnerConfig {
    pub dht_config: DhtSecureConfig,
    pub threaded: bool,
    proxy_server: Option<CString>,
    push_node_id: Option<CString>,
    push_token: Option<CString>,
    push_topic: Option<CString>,
    push_platform: Option<CString>,
    proxy_user_agent: Option<CString>,
    pub peer_discovery: bool,
    pub peer_publish: bool,
    pub server_ca: Option<Box<DhtCertificate>>,
    pub client_identity: Option<DhtIdentity>,
    pub log: bool,
    status_callback: Option<StatusCallback>,
    certificate_store: Option<CertificateStore>,
}

fn string_ptr(value: &Option<CString>) -> *const libc::c_char {
    value.as_ref().map_or(ptr::null(), |value| value.as_ptr())
}

macro_rules! string_setting {
    ($method:ident, $field:ident) => {
        pub fn $method(&mut self, value: &str) -> io::Result<()> {
            self.$field = Some(CString::new(value)?);
            Ok(())
        }
    };
}

impl DhtRunnerConfig {
    pub fn new() -> Box<DhtRunnerConfig> {
        Box::new(DhtRunnerConfig {
            dht_config: DhtSecureConfig {
                node_config: DhtNodeConfig {
                    node_id: InfoHash::new(),
                    network: 0,
                    is_bootstrap: false,
                    maintain_storage: false,
                    persist_path: None,
                },
                id: None,
            },
            threaded: true,
            proxy_server: None,
            push_node_id: None,
            push_token: None,
            push_topic: None,
            push_platform: None,
            proxy_user_agent: None,
            peer_discovery: false,
            peer_publish: false,
            server_ca: None,
            client_identity: None,
            log: false,
            status_callback: None,
            certificate_store: None,
        })
    }

    string_setting!(set_proxy_server, proxy_server);
    string_setting!(set_push_node_id, push_node_id);
    string_setting!(set_push_token, push_token);
    string_setting!(set_push_topic, push_topic);
    string_setting!(set_push_platform, push_platform);
    string_setting!(set_proxy_user_agent, proxy_user_agent);

    pub fn set_status_callback(
        &mut self,
        callback: impl FnMut(NodeStatus, NodeStatus) + Send + 'static,
    ) {
        self.status_callback = Some(Box::new(callback));
    }

    pub fn set_certificate_store(
        &mut self,
        callback: impl FnMut(&PkId) -> Vec<Box<DhtCertificate>> + Send + 'static,
    ) {
        self.certificate_store = Some(Box::new(callback));
    }

    pub fn set_identity(&mut self, certificate: Box<DhtCertificate>, privatekey: Box<PrivateKey>) {
        self.dht_config.id = Some(DhtIdentity {
            certificate,
            privatekey,
        });
    }

    fn raw(&self) -> ffi::DhtRunnerConfig {
        let node = &self.dht_config.node_config;
        let empty_identity = || ffi::DhtIdentity {
            privatekey: ptr::null_mut(),
            certificate: ptr::null_mut(),
        };
        ffi::DhtRunnerConfig {
            dht_config: ffi::DhtSecureConfig {
                node_config: ffi::DhtNodeConfig {
                    node_id: InfoHash { d: node.node_id.d },
                    network: node.network,
                    is_bootstrap: node.is_bootstrap,
                    maintain_storage: node.maintain_storage,
                    persist_path: string_ptr(&node.persist_path),
                },
                id: self
                    .dht_config
                    .id
                    .as_ref()
                    .map_or_else(empty_identity, DhtIdentity::raw),
            },
            threaded: self.threaded,
            proxy_server: string_ptr(&self.proxy_server),
            push_node_id: string_ptr(&self.push_node_id),
            push_token: string_ptr(&self.push_token),
            push_topic: string_ptr(&self.push_topic),
            push_platform: string_ptr(&self.push_platform),
            proxy_user_agent: string_ptr(&self.proxy_user_agent),
            peer_discovery: self.peer_discovery,
            peer_publish: self.peer_publish,
            server_ca: self
                .server_ca
                .as_ref()
                .map_or(ptr::null_mut(), |certificate| certificate.as_ptr()),
            client_identity: self
                .client_identity
                .as_ref()
                .map_or_else(empty_identity, DhtIdentity::raw),
            log: self.log,
        }
    }
}

impl DhtNodeConfig {
    string_setting!(set_persist_path, persist_path);
}

struct GetHandler {
    get_cb: Box<dyn FnMut(Box<Value>) -> bool + Send>,
    done_cb: Box<dyn FnOnce(bool) + Send>,
}

impl GetHandler {
    fn get_cb(&mut self, v: Box<Value>) -> bool {
        (self.get_cb)(v)
    }
}

fn callback<T>(fallback: T, operation: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(fallback)
}

fn result(code: i32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code))
    }
}

extern "C" fn get_handler_cb(value: *const ffi::Value, ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return true;
    }
    callback(false, || unsafe {
        let handler = ptr as *mut GetHandler;
        (*handler).get_cb(Value::copy_from_received(value).expect("value copy failed"))
    })
}

extern "C" fn done_handler_cb(ok: bool, ptr: *mut c_void) {
    callback((), || unsafe {
        let handler = Box::from_raw(ptr as *mut GetHandler);
        (handler.done_cb)(ok)
    })
}

struct PutHandler {
    done_cb: Box<dyn FnOnce(bool) + Send>,
}

extern "C" fn put_handler_done(ok: bool, ptr: *mut c_void) {
    callback((), || unsafe {
        let handler = Box::from_raw(ptr as *mut PutHandler);
        (handler.done_cb)(ok)
    })
}

struct ListenHandler {
    cb: Box<dyn FnMut(Box<Value>, bool) -> bool + Send>,
}

impl ListenHandler {
    fn cb(&mut self, v: Box<Value>, expired: bool) -> bool {
        (self.cb)(v, expired)
    }
}

extern "C" fn listen_handler(value: *const ffi::Value, expired: bool, ptr: *mut c_void) -> bool {
    callback(false, || unsafe {
        let handler = ptr as *mut ListenHandler;
        (*handler).cb(
            Value::copy_from_received(value).expect("value copy failed"),
            expired,
        )
    })
}

extern "C" fn listen_handler_done(ptr: *mut c_void) {
    callback((), || unsafe {
        drop(Box::from_raw(ptr as *mut ListenHandler));
    })
}

extern "C" fn shutdown_handler(ptr: *mut c_void) {
    callback((), || unsafe {
        let handler = Box::from_raw(ptr as *mut Box<dyn FnOnce() + Send>);
        handler();
    })
}

extern "C" fn context_released(data: *mut c_void) {
    callback((), || unsafe {
        drop(Box::from_raw(data as *mut Mutex<ContextCallbacks>));
    });
}

extern "C" fn status_handler(ipv4: i32, ipv6: i32, data: *mut c_void) {
    callback((), || unsafe {
        let mut handlers = (*(data as *mut Mutex<ContextCallbacks>))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(handler) = &mut handlers.status {
            handler(NodeStatus::from_raw(ipv4), NodeStatus::from_raw(ipv6));
        }
    });
}

extern "C" fn certificate_store_handler(
    id: *const PkId,
    emit: ffi::CertificateCallback,
    emit_data: *mut c_void,
    data: *mut c_void,
) {
    callback((), || unsafe {
        let mut handlers = (*(data as *mut Mutex<ContextCallbacks>))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(handler) = &mut handlers.store {
            for certificate in handler(&*id) {
                emit(certificate.as_ptr(), emit_data);
            }
        }
    });
}

struct QueryHandler {
    callback: Box<dyn FnMut(QueryResult) -> bool + Send>,
    done: Box<dyn FnOnce(bool) + Send>,
}

extern "C" fn query_handler(fields: *const ffi::QueryResult, data: *mut c_void) -> bool {
    callback(false, || unsafe {
        let fields = &*fields;
        let user_type = if fields.fields & 16 != 0 {
            Some(if fields.user_type.size == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(fields.user_type.data, fields.user_type.size).to_vec()
            })
        } else {
            None
        };
        let result = QueryResult {
            id: (fields.fields & 1 != 0).then_some(fields.id),
            value_type: (fields.fields & 2 != 0).then_some(fields.value_type),
            seq: (fields.fields & 4 != 0).then_some(fields.seq),
            owner: (fields.fields & 8 != 0).then_some(InfoHash { d: fields.owner.d }),
            user_type,
        };
        ((*(data as *mut QueryHandler)).callback)(result)
    })
}

extern "C" fn query_done(ok: bool, data: *mut c_void) {
    callback((), || unsafe {
        let handler = Box::from_raw(data as *mut QueryHandler);
        (handler.done)(ok);
    });
}

type CertificateCompletion = Box<dyn FnOnce(Option<Box<DhtCertificate>>) + Send>;

struct CertificateHandler {
    callback: Option<CertificateCompletion>,
}

extern "C" fn certificate_handler(certificate: *const ffi::DhtCertificate, data: *mut c_void) {
    callback((), || unsafe {
        let handler = &mut *(data as *mut CertificateHandler);
        if let Some(done) = handler.callback.take() {
            done(DhtCertificate::from_raw(ffi::dht_certificate_ref(certificate)).ok());
        }
    });
}

extern "C" fn certificate_released(data: *mut c_void) {
    callback((), || unsafe {
        let mut handler = Box::from_raw(data as *mut CertificateHandler);
        if let Some(done) = handler.callback.take() {
            done(None);
        }
    });
}

#[allow(clippy::boxed_local)]
impl DhtRunner {
    pub fn new() -> Box<DhtRunner> {
        unsafe { Self::from_raw(ffi::dht_runner_new()).expect("runner allocation failed") }
    }

    pub fn run(&mut self, port: u16) -> io::Result<()> {
        result(unsafe { ffi::dht_runner_run(self.as_ptr(), port) })
    }

    pub fn run_config(&mut self, port: u16, config: Box<DhtRunnerConfig>) -> io::Result<()> {
        self.run_bind("0.0.0.0", "::", port, config)
    }

    pub fn run_bind(
        &mut self,
        ipv4: &str,
        ipv6: &str,
        port: u16,
        mut config: Box<DhtRunnerConfig>,
    ) -> io::Result<()> {
        let ipv4 = CString::new(ipv4)?;
        let ipv6 = CString::new(ipv6)?;
        let context = ffi::DhtRunnerContext {
            status_cb: config
                .status_callback
                .as_ref()
                .map(|_| status_handler as extern "C" fn(_, _, _)),
            certificate_store_cb: config
                .certificate_store
                .as_ref()
                .map(|_| certificate_store_handler as extern "C" fn(_, _, _, _)),
            released_cb: Some(context_released),
            user_data: Box::into_raw(Box::new(Mutex::new(ContextCallbacks {
                status: config.status_callback.take(),
                store: config.certificate_store.take(),
            })))
            .cast(),
        };
        result(unsafe {
            ffi::dht_runner_run_bind(
                self.as_ptr(),
                ipv4.as_ptr(),
                ipv6.as_ptr(),
                port,
                &config.raw(),
                &context,
            )
        })
    }

    pub fn bootstrap(&mut self, host: &str, service: u16) -> io::Result<()> {
        let host = CString::new(host)?;
        let service = CString::new(service.to_string())?;
        unsafe { ffi::dht_runner_bootstrap(self.as_ptr(), host.as_ptr(), service.as_ptr()) }
        Ok(())
    }

    pub fn node_id(&self) -> InfoHash {
        unsafe { ffi::dht_runner_get_node_id(self.as_ptr()) }
    }

    pub fn id(&self) -> InfoHash {
        unsafe { ffi::dht_runner_get_id(self.as_ptr()) }
    }

    pub fn public_key(&self) -> Option<Box<PublicKey>> {
        unsafe { PublicKey::from_raw(ffi::dht_runner_get_publickey(self.as_ptr())).ok() }
    }

    pub fn register_certificate(&mut self, certificate: &DhtCertificate) -> io::Result<()> {
        result(unsafe { ffi::dht_runner_register_certificate(self.as_ptr(), certificate.as_ptr()) })
    }

    pub fn find_certificate(
        &mut self,
        id: &PkId,
        callback: impl FnOnce(Option<Box<DhtCertificate>>) + Send + 'static,
    ) {
        let handler = Box::new(CertificateHandler {
            callback: Some(Box::new(callback)),
        });
        unsafe {
            ffi::dht_runner_find_certificate(
                self.as_ptr(),
                id,
                certificate_handler,
                certificate_released,
                Box::into_raw(handler).cast(),
            );
        }
    }

    pub fn register_type(
        &mut self,
        id: u16,
        name: &str,
        expiration_seconds: u64,
        insecure: bool,
    ) -> io::Result<()> {
        let name = CString::new(name)?;
        result(unsafe {
            ffi::dht_runner_register_type(
                self.as_ptr(),
                id,
                name.as_ptr(),
                expiration_seconds,
                insecure,
            )
        })
    }

    pub fn connectivity_changed(&mut self) -> io::Result<()> {
        result(unsafe { ffi::dht_runner_connectivity_changed(self.as_ptr()) })
    }

    /// Deliver owned values that callbacks may mutate or move to another thread.
    pub fn get(
        &mut self,
        h: &InfoHash,
        get_cb: impl FnMut(Box<Value>) -> bool + Send + 'static,
        done_cb: impl FnOnce(bool) + Send + 'static,
    ) {
        let handler = Box::new(GetHandler {
            get_cb: Box::new(get_cb),
            done_cb: Box::new(done_cb),
        });
        let handler = Box::into_raw(handler) as *mut c_void;
        unsafe { ffi::dht_runner_get(self.as_ptr(), h, get_handler_cb, done_handler_cb, handler) }
    }

    pub fn get_filtered(
        &mut self,
        hash: &InfoHash,
        filter: &str,
        get_cb: impl FnMut(Box<Value>) -> bool + Send + 'static,
        done_cb: impl FnOnce(bool) + Send + 'static,
    ) -> io::Result<()> {
        let filter = CString::new(filter)?;
        let handler = Box::new(GetHandler {
            get_cb: Box::new(get_cb),
            done_cb: Box::new(done_cb),
        });
        unsafe {
            ffi::dht_runner_get_filtered(
                self.as_ptr(),
                hash,
                filter.as_ptr(),
                get_handler_cb,
                done_handler_cb,
                Box::into_raw(handler).cast(),
            );
        }
        Ok(())
    }

    pub fn query(
        &mut self,
        hash: &InfoHash,
        query: &str,
        query_cb: impl FnMut(QueryResult) -> bool + Send + 'static,
        done_cb: impl FnOnce(bool) + Send + 'static,
    ) -> io::Result<()> {
        let query = CString::new(query)?;
        let handler = Box::new(QueryHandler {
            callback: Box::new(query_cb),
            done: Box::new(done_cb),
        });
        unsafe {
            ffi::dht_runner_query(
                self.as_ptr(),
                hash,
                query.as_ptr(),
                query_handler,
                query_done,
                Box::into_raw(handler).cast(),
            );
        }
        Ok(())
    }

    pub fn put(
        &mut self,
        h: &InfoHash,
        v: Box<Value>,
        done_cb: impl FnOnce(bool) + Send + 'static,
        permanent: bool,
    ) {
        let handler = Box::new(PutHandler {
            done_cb: Box::new(done_cb),
        });
        let handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            ffi::dht_runner_put(
                self.as_ptr(),
                h,
                v.as_ptr(),
                put_handler_done,
                handler,
                permanent,
            )
        }
    }

    pub fn put_signed(
        &mut self,
        h: &InfoHash,
        v: Box<Value>,
        done_cb: impl FnOnce(bool) + Send + 'static,
        permanent: bool,
    ) {
        let handler = Box::new(PutHandler {
            done_cb: Box::new(done_cb),
        });
        let handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            ffi::dht_runner_put_signed(
                self.as_ptr(),
                h,
                v.as_ptr(),
                put_handler_done,
                handler,
                permanent,
            )
        }
    }

    pub fn put_encrypted(
        &mut self,
        h: &InfoHash,
        to: &PkId,
        v: Box<Value>,
        done_cb: impl FnOnce(bool) + Send + 'static,
        permanent: bool,
    ) {
        let handler = Box::new(PutHandler {
            done_cb: Box::new(done_cb),
        });
        let handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            ffi::dht_runner_put_encrypted(
                self.as_ptr(),
                h,
                to,
                v.as_ptr(),
                put_handler_done,
                handler,
                permanent,
            )
        }
    }

    pub fn cancel_put(&mut self, h: &InfoHash, vid: u64) {
        unsafe { ffi::dht_runner_cancel_put(self.as_ptr(), h, vid) }
    }

    /// Registers an owned callback receiving ordinary owned `Box<Value>` objects.
    /// It is released after cancellation or `join()`.
    /// Borrowed callbacks cannot outlive their stack frame:
    ///
    /// ```compile_fail
    /// use opendht::{DhtRunner, InfoHash};
    /// let mut runner = DhtRunner::new();
    /// let mut callback = |_, _| true;
    /// runner.listen(&InfoHash::new(), &mut callback);
    /// ```
    ///
    /// Captures must be safe to transfer to the DHT thread:
    ///
    /// ```compile_fail
    /// use opendht::{DhtRunner, InfoHash};
    /// use std::rc::Rc;
    /// let mut runner = DhtRunner::new();
    /// let state = Rc::new(42);
    /// runner.listen(&InfoHash::new(), move |_, _| { println!("{state}"); true });
    /// ```
    pub fn listen(
        &mut self,
        h: &InfoHash,
        cb: impl FnMut(Box<Value>, bool) -> bool + Send + 'static,
    ) -> io::Result<Box<OpToken>> {
        let handler = Box::new(ListenHandler { cb: Box::new(cb) });
        let handler = Box::into_raw(handler) as *mut c_void;
        unsafe {
            OpToken::from_raw(ffi::dht_runner_listen(
                self.as_ptr(),
                h,
                listen_handler,
                listen_handler_done,
                handler,
            ))
        }
    }

    pub fn cancel_listen(&mut self, h: &InfoHash, token: Box<OpToken>) {
        unsafe { ffi::dht_runner_cancel_listen(self.as_ptr(), h, token.as_ptr()) }
    }

    pub fn listen_filtered(
        &mut self,
        hash: &InfoHash,
        filter: &str,
        cb: impl FnMut(Box<Value>, bool) -> bool + Send + 'static,
    ) -> io::Result<Box<OpToken>> {
        let filter = CString::new(filter)?;
        let handler = Box::new(ListenHandler { cb: Box::new(cb) });
        unsafe {
            OpToken::from_raw(ffi::dht_runner_listen_filtered(
                self.as_ptr(),
                hash,
                filter.as_ptr(),
                listen_handler,
                listen_handler_done,
                Box::into_raw(handler).cast(),
            ))
        }
    }

    pub fn shutdown(&mut self, done_cb: impl FnOnce() + Send + 'static) {
        let handler: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(done_cb));
        unsafe {
            ffi::dht_runner_shutdown(
                self.as_ptr(),
                shutdown_handler,
                Box::into_raw(handler).cast(),
            )
        }
    }

    pub fn join(&mut self) -> io::Result<()> {
        result(unsafe { ffi::dht_runner_join(self.as_ptr()) })
    }
    pub fn loop_once(&mut self) -> io::Result<()> {
        result(unsafe { ffi::dht_runner_loop(self.as_ptr()) })
    }
    pub fn is_running(&self) -> bool {
        unsafe { ffi::dht_runner_is_running(self.as_ptr()) }
    }
    pub fn bound_port(&self, family: libc::sa_family_t) -> u16 {
        unsafe { ffi::dht_runner_get_bound_port(self.as_ptr(), family) }
    }

    pub fn ping(&mut self, address: SocketAddr, done_cb: impl FnOnce(bool) + Send + 'static) {
        let address = OsSocketAddr::from(address);
        let handler = Box::new(PutHandler {
            done_cb: Box::new(done_cb),
        });
        unsafe {
            ffi::dht_runner_ping(
                self.as_ptr(),
                address.as_ptr().cast_mut(),
                address.len(),
                put_handler_done,
                Box::into_raw(handler).cast(),
            );
        }
    }

    pub fn set_push_notification_token(&mut self, value: &str) -> io::Result<()> {
        let value = CString::new(value)?;
        result(unsafe {
            ffi::dht_runner_set_push_notification_token(self.as_ptr(), value.as_ptr())
        })
    }
    pub fn set_push_notification_topic(&mut self, value: &str) -> io::Result<()> {
        let value = CString::new(value)?;
        result(unsafe {
            ffi::dht_runner_set_push_notification_topic(self.as_ptr(), value.as_ptr())
        })
    }
    pub fn set_push_notification_platform(&mut self, value: &str) -> io::Result<()> {
        let value = CString::new(value)?;
        result(unsafe {
            ffi::dht_runner_set_push_notification_platform(self.as_ptr(), value.as_ptr())
        })
    }
    pub fn push_notification_received(
        &mut self,
        data: &[(&str, &str)],
    ) -> io::Result<PushNotification> {
        let keys = data
            .iter()
            .map(|(key, _)| CString::new(*key))
            .collect::<Result<Vec<_>, _>>()?;
        let values = data
            .iter()
            .map(|(_, value)| CString::new(*value))
            .collect::<Result<Vec<_>, _>>()?;
        let key_ptrs = keys.iter().map(|key| key.as_ptr()).collect::<Vec<_>>();
        let value_ptrs = values
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        let token = unsafe {
            PushToken::from_raw(ffi::dht_runner_push_notification_received(
                self.as_ptr(),
                key_ptrs.as_ptr(),
                value_ptrs.as_ptr(),
                data.len(),
            ))?
        };
        Ok(PushNotification {
            token,
            result: None,
        })
    }

    pub fn public_addresses(&self) -> Vec<SocketAddr> {
        let mut result = Vec::new();
        unsafe {
            let original = ffi::dht_runner_get_public_address(self.as_ptr());
            let mut addresses = original;
            while !addresses.is_null() && !(*addresses).is_null() {
                let length = match (**addresses).sa_family as i32 {
                    libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>(),
                    libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>(),
                    _ => 0,
                };
                let sock = OsSocketAddr::copy_from_raw(*addresses, length as _).into_addr();
                if let Some(address) = sock {
                    result.push(address);
                }
                addresses = addresses.add(1);
            }
            ffi::dht_sockaddr_array_delete(original);
        }
        result
    }
}
