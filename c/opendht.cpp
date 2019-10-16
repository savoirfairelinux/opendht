#include "opendht_c.h"
#include "opendht.h"

#ifdef __cplusplus
extern "C" {
#endif

// dht::InfoHash
const char* dht_infohash_print(const dht_infohash* h)
{
    return reinterpret_cast<const dht::InfoHash*>(h)->to_c_str();
}

void dht_infohash_random(dht_infohash* h)
{
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash::getRandom();
}

void dht_blob_delete(dht_blob* data)
{
    delete reinterpret_cast<dht::Blob*>(data->ptr);
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

int dht_publickey_pack(dht_publickey* pk, char* out, size_t* outlen)
{
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

bool dht_publickey_check_signature(const dht_publickey* pk, const char* data, size_t data_size, const char* signature, size_t signature_size)
{
    return reinterpret_cast<const dht::crypto::PublicKey*>(pk)->checkSignature((const uint8_t*)data, data_size, (const uint8_t*)signature, signature_size);
}

dht_blob dht_publickey_encrypt(const dht_publickey* pk, const char* data, size_t data_size)
{
    dht_blob ret;
    ret.ptr = new dht::Blob;
    *reinterpret_cast<dht::Blob*>(ret.ptr) = reinterpret_cast<const dht::crypto::PublicKey*>(pk)->encrypt((const uint8_t*)data, data_size);
    ret.data = reinterpret_cast<dht::Blob*>(ret.ptr)->data();
    ret.data_length = reinterpret_cast<dht::Blob*>(ret.ptr)->size();
    return ret;
}

// dht::DhtRunner
dht_runner* dht_runner_new() {
    return reinterpret_cast<dht_runner*>(new dht::DhtRunner);
}

void dht_runner_delete(dht_runner* runner) {
    delete reinterpret_cast<dht::DhtRunner*>(runner);
}

void dht_runner_run(dht_runner* r, in_port_t port)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    runner->run(port, {}, true);
}

void dht_runner_ping(dht_runner* r, struct sockaddr* addr, socklen_t addr_len)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    runner->bootstrap(dht::SockAddr(addr, addr_len));
}

void dht_runner_get(dht_runner* r, const dht_infohash* h, dht_get_cb cb, dht_done_cb done_cb, void* cb_user_data)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    runner->get(*hash, [cb,cb_user_data](std::shared_ptr<dht::Value> value){
        return cb(reinterpret_cast<dht_value*>(value.get()), cb_user_data);
    }, [done_cb, cb_user_data](bool ok){
        done_cb(ok, cb_user_data);
    });
}

#ifdef __cplusplus
}
#endif
