use opendht::crypto::{DhtCertificate, DhtIdentity, PrivateKey, PublicKey};
use opendht::{DhtRunner, DhtRunnerConfig, InfoHash, Value};
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc, mpsc};
use std::time::Duration;

#[test]
fn value_metadata_and_borrowed_strings() {
    let mut value = Value::with_id(b"binary\0value", 42);
    value.set_user_type("application/octet-stream").unwrap();
    value.set_value_type(17);
    value.set_seq(23);
    value.set_priority(1);
    value.set_push_type("audioCall").unwrap();
    assert_eq!(value.id(), 42);
    assert_eq!(value.as_bytes(), b"binary\0value");
    assert_eq!(value.user_type().unwrap(), "application/octet-stream");
    assert_eq!(value.user_type().unwrap(), "application/octet-stream");
    assert_eq!(value.value_type(), 17);
    assert_eq!(value.seq(), 23);
    assert_eq!(value.priority(), 1);
    assert_eq!(value.push_type().unwrap(), "audioCall");
    assert!(value.owner().is_none());
    assert!(value.recipient().is_zero());
    assert!(Value::new("").as_bytes().is_empty());
}

#[test]
fn crypto_errors_are_results() {
    assert!(PrivateKey::new(1).is_err());
    assert!(PrivateKey::from_bytes(&[1, 2, 3], "").is_err());
    assert!(PublicKey::new("not a key").is_err());
    assert!(DhtCertificate::from_bytes(&[1, 2, 3]).is_err());
}

#[test]
fn binary_crypto_and_password_slices() {
    let private = PrivateKey::new(2048).unwrap();
    let backing = String::from("password-extra");
    let password = &backing[..8];
    let packed = private.serialize(password).unwrap();
    let restored = PrivateKey::from_bytes(&packed, password).unwrap();
    assert!(PrivateKey::from_bytes(&packed, "wrong").is_err());
    assert!(PrivateKey::from_bytes(&packed, "bad\0password").is_err());
    let mut public = PublicKey::new(&restored.public_key().pack().unwrap()).unwrap();
    public.unpack(private.public_key().pack().unwrap()).unwrap();
    let data = b"binary\0message\xff";
    let signature = restored.sign(data).unwrap();
    assert!(public.check_signature(data, &signature));
    assert!(!public.check_signature(b"changed", &signature));
    let encrypted = public.encrypt(data).unwrap();
    assert_eq!(restored.decrypt(&encrypted.as_bytes()).unwrap().as_bytes(), data);
    assert!(restored.decrypt(b"invalid").is_err());
    let plain = private.serialize("").unwrap();
    assert!(PrivateKey::from_bytes(&plain, "").is_ok());
}

#[test]
fn identity_persistence() {
    let identity = DhtIdentity::new("binding regression").unwrap();
    let certificate = identity.certificate.serialize().unwrap();
    let restored = DhtCertificate::from_bytes(&certificate).unwrap();
    assert!(identity.certificate.id() == restored.id());
    assert!(DhtIdentity::generate("child", &identity).is_ok());
    assert!(DhtIdentity::new_ec("elliptic curve").is_ok());
}

struct DropCounter(Arc<AtomicUsize>);

impl Drop for DropCounter {
    fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn join_releases_pending_callbacks_and_allows_restart() {
    let mut runner = DhtRunner::new();
    let mut config = DhtRunnerConfig::new();
    config.threaded = false;
    config.set_proxy_user_agent("regression").unwrap();
    config.set_proxy_user_agent("replacement").unwrap();
    runner.run_config(0, config).unwrap();
    assert!(runner.is_running());
    assert_ne!(runner.bound_port(libc::AF_INET as _), 0);
    let hash = InfoHash::get("callback ownership");
    let released = Arc::new(AtomicUsize::new(0));
    let counter = DropCounter(released.clone());
    let token = runner.listen(&hash, move |_, _| { let _ = &counter; true }).unwrap();
    let (sent, received) = mpsc::channel();
    runner.get(&hash, |_| true, move |ok| { sent.send(ok).unwrap(); });
    runner.join().unwrap();
    assert_eq!(released.load(Ordering::SeqCst), 1);
    assert!(!received.recv_timeout(Duration::from_secs(5)).unwrap());
    drop(token);
    assert!(!runner.is_running());
    runner.run(0).unwrap();
    runner.join().unwrap();
}

#[test]
fn nonthreaded_loop_executes_owned_callbacks() {
    let mut runner = DhtRunner::new();
    let mut config = DhtRunnerConfig::new();
    config.threaded = false;
    runner.run_config(0, config).unwrap();
    let hash = InfoHash::get("loop progress");
    let seen = Arc::new(AtomicUsize::new(0));
    let callback_seen = seen.clone();
    let token = runner.listen(&hash, move |value, expired| {
        if !expired {
            assert_eq!(value.as_bytes(), b"test");
            callback_seen.fetch_add(1, Ordering::SeqCst);
        }
        true
    }).unwrap();
    runner.put(&hash, Value::new("test"), |_| {}, false);
    runner.loop_once().unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    runner.cancel_listen(&hash, token);
    runner.join().unwrap();
}

#[test]
fn shutdown_owns_its_callback_and_contains_panics() {
    let mut runner = DhtRunner::new();
    let (sent, received) = mpsc::channel();
    runner.shutdown(move || { sent.send(42).unwrap(); });
    assert_eq!(received.recv_timeout(Duration::from_secs(5)).unwrap(), 42);
    runner.get(&InfoHash::new(), |_| true, |_| panic!("callback panic must not unwind into C"));
}

#[test]
fn startup_errors_reach_rust() {
    let socket4 = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = socket4.local_addr().unwrap().port();
    let _socket6 = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, port)).unwrap();
    assert!(DhtRunner::new().run(port).is_err());
}