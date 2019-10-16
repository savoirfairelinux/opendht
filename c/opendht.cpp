#include "opendht_c.h"
#include "opendht.h"

using ValueSp = std::shared_ptr<dht::Value>;

#ifdef __cplusplus
extern "C" {
#endif

// dht::InfoHash
const char* dht_infohash_print(const dht_infohash* h)
{
    return reinterpret_cast<const dht::InfoHash*>(h)->to_c_str();
}

void dht_infohash_zero(dht_infohash* h) {
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash{};
}

void dht_infohash_random(dht_infohash* h)
{
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash::getRandom();
}

bool dht_infohash_is_zero(const dht_infohash* h) {
    return static_cast<bool>(*reinterpret_cast<const dht::InfoHash*>(h));
}

const char* dht_pkid_print(const dht_pkid* h)
{
    return reinterpret_cast<const dht::PkId*>(h)->to_c_str();
}

// dht::Blob
void dht_blob_delete(dht_blob* data)
{
    delete reinterpret_cast<dht::Blob*>(data);
}

dht_data_view dht_blob_get_data(const dht_blob* data)
{
    dht_data_view view;
    view.data = reinterpret_cast<const dht::Blob*>(data)->data();
    view.size = reinterpret_cast<const dht::Blob*>(data)->size();
    return view;
}

// dht::Value
dht_data_view dht_value_get_data(const dht_value* data)
{
    const ValueSp& vsp(*reinterpret_cast<const ValueSp*>(data));
    dht_data_view view;
    view.data = vsp->data.data();
    view.size = vsp->data.size();
    return view;
}

dht_value* dht_value_new(const uint8_t* data, size_t size) {
    return reinterpret_cast<dht_value*>(new ValueSp(std::make_shared<dht::Value>(data, size)));
}

dht_value* dht_value_ref(const dht_value* v) {
    return reinterpret_cast<dht_value*>(new ValueSp(*reinterpret_cast<const ValueSp*>(v)));
}

void dht_value_unref(dht_value* v) {
    delete reinterpret_cast<ValueSp*>(v);
}

// dht::crypto::PublicKey
dht_publickey* dht_publickey_new() {
    return reinterpret_cast<dht_publickey*>(new dht::crypto::PublicKey);
}

void dht_publickey_delete(dht_publickey* pk) {
    delete reinterpret_cast<dht::crypto::PublicKey*>(pk);
}

int dht_publickey_unpack(dht_publickey* pk, const uint8_t* dat, size_t dat_size) {
    try {
        reinterpret_cast<dht::crypto::PublicKey*>(pk)->unpack(dat, dat_size);
    } catch (const dht::crypto::CryptoException& e) {
        return -1;
    }
    return 0;
}

int dht_publickey_pack(dht_publickey* pk, char* out, size_t* outlen) {
    return gnutls_pubkey_export(reinterpret_cast<dht::crypto::PublicKey*>(pk)->pk, GNUTLS_X509_FMT_DER, out, outlen);
}

dht_infohash dht_publickey_get_id(const dht_publickey* pk) {
    dht_infohash h;
    *reinterpret_cast<dht::InfoHash*>(&h) = reinterpret_cast<const dht::crypto::PublicKey*>(pk)->getId();
    return h;
}

dht_pkid dht_publickey_get_long_id(const dht_publickey* pk) {
    dht_pkid h;
    *reinterpret_cast<dht::PkId*>(&h) = reinterpret_cast<const dht::crypto::PublicKey*>(pk)->getLongId();
    return h;
}

bool dht_publickey_check_signature(const dht_publickey* pk, const char* data, size_t data_size, const char* signature, size_t signature_size) {
    return reinterpret_cast<const dht::crypto::PublicKey*>(pk)->checkSignature((const uint8_t*)data, data_size, (const uint8_t*)signature, signature_size);
}

dht_blob* dht_publickey_encrypt(const dht_publickey* pk, const char* data, size_t data_size) {
    auto rdata = new dht::Blob;
    *rdata = reinterpret_cast<const dht::crypto::PublicKey*>(pk)->encrypt((const uint8_t*)data, data_size);
    return (dht_blob*)rdata;
}

dht_privatekey* dht_privatekey_generate(unsigned key_length_bits) {
    if (key_length_bits == 0)
        key_length_bits = 4096;
    return reinterpret_cast<dht_privatekey*>(new dht::crypto::PrivateKey(dht::crypto::PrivateKey::generate(key_length_bits)));
}

dht_privatekey* dht_privatekey_import(const uint8_t* dat, size_t dat_size, const char* password) {
    try {
        return reinterpret_cast<dht_privatekey*>(new dht::crypto::PrivateKey(dat, dat_size, password));
    } catch (const dht::crypto::CryptoException& e) {
        return nullptr;
    }
}

dht_publickey* dht_privatekey_get_publickey(const dht_privatekey* key) {
    return reinterpret_cast<dht_publickey*>(new dht::crypto::PublicKey(reinterpret_cast<const dht::crypto::PrivateKey*>(key)->getPublicKey()));
}

void dht_privatekey_delete(dht_privatekey* pk) {
    delete reinterpret_cast<dht::crypto::PrivateKey*>(pk);
}

// dht::DhtRunner
dht_runner* dht_runner_new() {
    return reinterpret_cast<dht_runner*>(new dht::DhtRunner);
}

void dht_runner_delete(dht_runner* runner) {
    delete reinterpret_cast<dht::DhtRunner*>(runner);
}

void dht_runner_run(dht_runner* r, in_port_t port) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    runner->run(port, {}, true);
}

void dht_runner_ping(dht_runner* r, struct sockaddr* addr, socklen_t addr_len) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    runner->bootstrap(dht::SockAddr(addr, addr_len));
}

void dht_runner_bootstrap(dht_runner* r, const char* host, const char* service) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    runner->bootstrap(host, service);
}

void dht_runner_get(dht_runner* r, const dht_infohash* h, dht_get_cb cb, dht_done_cb done_cb, void* cb_user_data) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    runner->get(*hash, [cb,cb_user_data](std::shared_ptr<dht::Value> value){
        return cb(reinterpret_cast<const dht_value*>(&value), cb_user_data);
    }, [done_cb, cb_user_data](bool ok){
        if (done_cb)
            done_cb(ok, cb_user_data);
    });
}

dht_op_token* dht_runner_listen(dht_runner* r, const dht_infohash* h, dht_value_cb cb, void* cb_user_data) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto fret = new std::future<size_t>;
    *fret = runner->listen(*hash, [cb,cb_user_data](const std::vector<std::shared_ptr<dht::Value>>& values, bool expired) {
        for (const auto& value : values) {
            if (not cb(reinterpret_cast<const dht_value*>(&value), expired, cb_user_data))
                return false;
        }
        return true;
    });
    return (dht_op_token*)fret;
}

void dht_runner_cancel_listen(dht_runner* r, const dht_infohash* h, dht_op_token* t) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto token = reinterpret_cast<std::future<size_t>*>(t);
    runner->cancelListen(*hash, std::move(*token));
}

void dht_op_token_delete(dht_op_token* token) {
    delete reinterpret_cast<std::future<size_t>*>(token);
}

void dht_runner_put(dht_runner* r, const dht_infohash* h, const dht_value* v, dht_done_cb done_cb, void* cb_user_data) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto value = reinterpret_cast<const ValueSp*>(v);
    runner->put(*hash, *value, [done_cb, cb_user_data](bool ok){
        if (done_cb)
            done_cb(ok, cb_user_data);
    });
}

void dht_runner_shutdown(dht_runner* r, dht_shutdown_cb done_cb, void* cb_user_data) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    runner->shutdown([done_cb, cb_user_data](){
        if (done_cb)
            done_cb(cb_user_data);
    });
}

#ifdef __cplusplus
}
#endif
