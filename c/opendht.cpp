#include "opendht_c.h"
#include "opendht.h"

using ValueSp = std::shared_ptr<dht::Value>;
using PrivkeySp = std::shared_ptr<dht::crypto::PrivateKey>;
using PubkeySp = std::shared_ptr<const dht::crypto::PublicKey>;
using CertSp = std::shared_ptr<dht::crypto::Certificate>;

#ifdef __cplusplus
extern "C" {
#endif

// dht::InfoHash

inline dht_infohash dht_infohash_to_c(const dht::InfoHash& h) {
    dht_infohash ret;
    *reinterpret_cast<dht::InfoHash*>(&ret) = h;
    return ret;
}

inline dht_pkid dht_pkid_to_c(const dht::PkId& h) {
    dht_pkid ret;
    *reinterpret_cast<dht::PkId*>(&ret) = h;
    return ret;
}

const char* dht_infohash_print(const dht_infohash* h) {
    return reinterpret_cast<const dht::InfoHash*>(h)->to_c_str();
}

void dht_infohash_zero(dht_infohash* h) {
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash{};
}

void dht_infohash_random(dht_infohash* h) {
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash::getRandom();
}

void dht_infohash_get(dht_infohash* h, const uint8_t* dat, size_t dat_size) {
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash::get(dat, dat_size);
}

void dht_infohash_get_from_string(dht_infohash* h, const char* dat) {
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash::get((const uint8_t*)dat, (size_t)strlen(dat));
}

bool dht_infohash_is_zero(const dht_infohash* h) {
    return !static_cast<bool>(*reinterpret_cast<const dht::InfoHash*>(h));
}

void dht_infohash_from_hex(dht_infohash* h, const char* dat) {
    *h = dht_infohash_to_c(dht::InfoHash(std::string(dat, HASH_LEN*2)));
}

const char* dht_pkid_print(const dht_pkid* h) {
    return reinterpret_cast<const dht::PkId*>(h)->to_c_str();
}

// dht::Blob
void dht_blob_delete(dht_blob* data) {
    delete reinterpret_cast<dht::Blob*>(data);
}

dht_data_view dht_blob_get_data(const dht_blob* data) {
    dht_data_view view;
    view.data = reinterpret_cast<const dht::Blob*>(data)->data();
    view.size = reinterpret_cast<const dht::Blob*>(data)->size();
    return view;
}

// dht::Value
dht_data_view dht_value_get_data(const dht_value* data) {
    const ValueSp& vsp(*reinterpret_cast<const ValueSp*>(data));
    dht_data_view view;
    view.data = vsp->data.data();
    view.size = vsp->data.size();
    return view;
}

dht_value_id dht_value_get_id(const dht_value* data) {
    const ValueSp& vsp(*reinterpret_cast<const ValueSp*>(data));
    return vsp->id;
}

dht_publickey* dht_value_get_owner(const dht_value* data) {
    const ValueSp& vsp(*reinterpret_cast<const ValueSp*>(data));
    return vsp->owner ? reinterpret_cast<dht_publickey*>(new PubkeySp(vsp->owner)) : nullptr;
}

dht_infohash dht_value_get_recipient(const dht_value* data) {
    const ValueSp& vsp(*reinterpret_cast<const ValueSp*>(data));
    return dht_infohash_to_c(vsp->recipient);
}

const char* dht_value_get_user_type(const dht_value* data) {
    const ValueSp& vsp(*reinterpret_cast<const ValueSp*>(data));
    return vsp->user_type.c_str();
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
dht_publickey* dht_publickey_import(const uint8_t* dat, size_t dat_size) {
    try {
        return reinterpret_cast<dht_publickey*>(new PubkeySp(std::make_shared<const dht::crypto::PublicKey>(dat, dat_size)));
    } catch (const dht::crypto::CryptoException& e) {
        return nullptr;
    }
}

void dht_publickey_delete(dht_publickey* pk) {
    delete reinterpret_cast<PubkeySp*>(pk);
}

int dht_publickey_export(const dht_publickey* pk, char* out, size_t* outlen) {
    const auto& pkey = *reinterpret_cast<const PubkeySp*>(pk);
    return pkey->pack((uint8_t*)out, outlen);
}

dht_infohash dht_publickey_get_id(const dht_publickey* pk) {
    const auto& pkey = *reinterpret_cast<const PubkeySp*>(pk);
    return dht_infohash_to_c(pkey->getId());
}

dht_pkid dht_publickey_get_long_id(const dht_publickey* pk) {
    const auto& pkey = *reinterpret_cast<const PubkeySp*>(pk);
    return dht_pkid_to_c(pkey->getLongId());
}

bool dht_publickey_check_signature(const dht_publickey* pk, const char* data, size_t data_size, const char* signature, size_t signature_size) {
    const auto& pkey = *reinterpret_cast<const PubkeySp*>(pk);
    return pkey->checkSignature((const uint8_t*)data, data_size, (const uint8_t*)signature, signature_size);
}

dht_blob* dht_publickey_encrypt(const dht_publickey* pk, const char* data, size_t data_size) {
    const auto& pkey = *reinterpret_cast<const PubkeySp*>(pk);
    auto rdata = new dht::Blob;
    *rdata = pkey->encrypt((const uint8_t*)data, data_size);
    return (dht_blob*)rdata;
}

// dht::crypto::PrivateKey
dht_privatekey* dht_privatekey_generate(unsigned key_length_bits) {
    if (key_length_bits == 0)
        key_length_bits = 4096;
    return reinterpret_cast<dht_privatekey*>(new PrivkeySp(std::make_shared<dht::crypto::PrivateKey>(dht::crypto::PrivateKey::generate(key_length_bits))));
}

dht_privatekey* dht_privatekey_import(const uint8_t* dat, size_t dat_size, const char* password) {
    try {
        return reinterpret_cast<dht_privatekey*>(new PrivkeySp(std::make_shared<dht::crypto::PrivateKey>(dat, dat_size, password)));
    } catch (const dht::crypto::CryptoException& e) {
        return nullptr;
    }
}

int dht_privatekey_export(const dht_privatekey* k, char* out, size_t* out_size, const char* password) {
    if (!out or !out_size or !*out_size)
        return -1;
    const auto& key = *reinterpret_cast<const PrivkeySp*>(k);
    return key->serialize((uint8_t*)out, out_size, password);
}

dht_publickey* dht_privatekey_get_publickey(const dht_privatekey* k) {
    const auto& key = *reinterpret_cast<const PrivkeySp*>(k);
    return reinterpret_cast<dht_publickey*>(new PubkeySp(std::make_shared<dht::crypto::PublicKey>(key->getPublicKey())));
}

void dht_privatekey_delete(dht_privatekey* pk) {
    delete reinterpret_cast<PrivkeySp*>(pk);
}

// dht::crypto::Certificate
dht_certificate* dht_certificate_import(const uint8_t* dat, size_t dat_size) {
    try {
        return reinterpret_cast<dht_certificate*>(new CertSp(std::make_shared<dht::crypto::Certificate>(dat, dat_size)));
    } catch (const dht::crypto::CryptoException& e) {
        return nullptr;
    }
}

void dht_certificate_delete(dht_certificate* c) {
    delete reinterpret_cast<CertSp*>(c);
}

dht_infohash dht_certificate_get_id(const dht_certificate* c) {
    const auto& cert = *reinterpret_cast<const CertSp*>(c);
    return dht_infohash_to_c(cert->getId());
}

dht_pkid dht_certificate_get_long_id(const dht_certificate* c) {
    const auto& cert = *reinterpret_cast<const CertSp*>(c);
    return dht_pkid_to_c(cert->getLongId());
}

dht_publickey* dht_certificate_get_publickey(const dht_certificate* c) {
    const auto& cert = *reinterpret_cast<const CertSp*>(c);
    return reinterpret_cast<dht_publickey*>(new PubkeySp(std::make_shared<dht::crypto::PublicKey>(cert->getPublicKey())));
}

// dht::crypto::Identity
inline dht::crypto::Identity dht_identity_from_c(const dht_identity* cid) {
    dht::crypto::Identity id {};
    if (cid and cid->privatekey)
        id.first = *reinterpret_cast<const PrivkeySp*>(cid->privatekey);
    if (cid and cid->certificate)
        id.second = *reinterpret_cast<const CertSp*>(cid->certificate);
    return id;
}

inline dht_identity dht_identity_to_c(const dht::crypto::Identity& id) {
    dht_identity cid {};
    cid.privatekey = id.first ? reinterpret_cast<dht_privatekey*>(new PrivkeySp(id.first)) : NULL;
    cid.certificate = id.second ? reinterpret_cast<dht_certificate*>(new CertSp(id.second)) : NULL;
    return cid;
}

OPENDHT_C_PUBLIC dht_identity dht_identity_generate(const char* common_name, const dht_identity* ca) {
    return dht_identity_to_c(dht::crypto::generateIdentity(common_name, dht_identity_from_c(ca)));
}

OPENDHT_C_PUBLIC void dht_identity_delete(dht_identity* id) {
    if (id->certificate) {
        dht_certificate_delete(id->certificate);
        id->certificate = NULL;
    }
    if (id->privatekey) {
        dht_privatekey_delete(id->privatekey);
        id->privatekey = NULL;
    }
}

// config
void dht_runner_config_default(dht_runner_config* config) {
    bzero(config, sizeof(dht_runner_config));
    config->threaded = true;
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

void dht_runner_run_config(dht_runner* r, in_port_t port, const dht_runner_config* conf) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    dht::DhtRunner::Config config;
    config.dht_config.node_config.is_bootstrap = conf->dht_config.node_config.is_bootstrap;
    config.dht_config.node_config.maintain_storage = conf->dht_config.node_config.maintain_storage;
    config.dht_config.node_config.node_id = *reinterpret_cast<const dht::InfoHash*>(&conf->dht_config.node_config.node_id);
    config.dht_config.node_config.network = conf->dht_config.node_config.network;
    config.dht_config.node_config.persist_path = conf->dht_config.node_config.persist_path
        ? std::string(conf->dht_config.node_config.persist_path) : std::string{};

    if (conf->dht_config.id.privatekey)
        config.dht_config.id.first = *reinterpret_cast<const PrivkeySp*>(conf->dht_config.id.privatekey);

    if (conf->dht_config.id.certificate)
        config.dht_config.id.second = *reinterpret_cast<const CertSp*>(conf->dht_config.id.certificate);

    config.threaded = conf->threaded;
    config.proxy_server = conf->proxy_server ? std::string(conf->proxy_server) : std::string{};
    config.push_node_id = conf->push_node_id ? std::string(conf->push_node_id) : std::string{};
    config.push_token = conf->push_token ? std::string(conf->push_token) : std::string{};
    config.peer_discovery = conf->peer_discovery;
    config.peer_publish = conf->peer_publish;
    runner->run(port, config);
}

void dht_runner_ping(dht_runner* r, struct sockaddr* addr, socklen_t addr_len) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    runner->bootstrap(dht::SockAddr(addr, addr_len));
}

void dht_runner_bootstrap(dht_runner* r, const char* host, const char* service) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    if (service)
        runner->bootstrap(host, service);
    else
        runner->bootstrap(host);
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

struct ScopeGuardCb {
    ScopeGuardCb(dht_shutdown_cb cb, void* data)
     : onDestroy(cb), userData(data) {}

    ~ScopeGuardCb() {
        if (onDestroy)
            onDestroy((void*)userData);
    }
private:
    const dht_shutdown_cb onDestroy;
    void const* userData;
};

dht_op_token* dht_runner_listen(dht_runner* r, const dht_infohash* h, dht_value_cb cb, dht_shutdown_cb done_cb, void* cb_user_data) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto fret = new std::future<size_t>;
    auto guard = done_cb ? std::make_shared<ScopeGuardCb>(done_cb, cb_user_data) : std::shared_ptr<ScopeGuardCb>{};
    *fret = runner->listen(*hash, [cb,cb_user_data, guard](const std::vector<std::shared_ptr<dht::Value>>& values, bool expired) {
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

void dht_runner_put(dht_runner* r, const dht_infohash* h, const dht_value* v, dht_done_cb done_cb, void* cb_user_data, bool permanent) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto value = reinterpret_cast<const ValueSp*>(v);
    runner->put(*hash, *value, [done_cb, cb_user_data](bool ok){
        if (done_cb)
            done_cb(ok, cb_user_data);
    }, dht::time_point::max(), permanent);
}

void dht_runner_put_signed(dht_runner* r, const dht_infohash* h, const dht_value* v, dht_done_cb done_cb, void* cb_user_data, bool permanent) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto value = reinterpret_cast<const ValueSp*>(v);
    runner->putSigned(*hash, *value, [done_cb, cb_user_data](bool ok){
        if (done_cb)
            done_cb(ok, cb_user_data);
    }, permanent);
}

void dht_runner_put_encrypted(dht_runner* r, const dht_infohash* h, const dht_infohash* to, const dht_value* v, dht_done_cb done_cb, void* cb_user_data, bool permanent) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto toHash = reinterpret_cast<const dht::InfoHash*>(to);
    auto value = reinterpret_cast<const ValueSp*>(v);
    runner->putEncrypted(*hash, *toHash, *value, [done_cb, cb_user_data](bool ok){
        if (done_cb)
            done_cb(ok, cb_user_data);
    }, permanent);
}

void dht_runner_cancel_put(dht_runner* r, const dht_infohash* h, dht_value_id value_id) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    runner->cancelPut(*hash, value_id);
}

void dht_runner_shutdown(dht_runner* r, dht_shutdown_cb done_cb, void* cb_user_data) {
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    runner->shutdown([done_cb, cb_user_data](){
        if (done_cb)
            done_cb(cb_user_data);
    });
}

dht_infohash dht_runner_get_node_id(const dht_runner* r) {
    auto runner = reinterpret_cast<const dht::DhtRunner*>(r);
    dht_infohash ret;
    *reinterpret_cast<dht::InfoHash*>(&ret) = runner->getNodeId();
    return ret;
}

dht_infohash dht_runner_get_id(const dht_runner* r) {
    auto runner = reinterpret_cast<const dht::DhtRunner*>(r);
    dht_infohash ret;
    *reinterpret_cast<dht::InfoHash*>(&ret) = runner->getId();
    return ret;
}

struct sockaddr** dht_runner_get_public_address(const dht_runner* r) {
    auto runner = reinterpret_cast<const dht::DhtRunner*>(r);
    auto addrs = const_cast<dht::DhtRunner*>(runner)->getPublicAddress();
    if (addrs.empty())
        return nullptr;
    auto ret = (struct sockaddr**)malloc(sizeof(struct sockaddr*) * (addrs.size() + 1));
    for (size_t i=0; i<addrs.size(); i++) {
        if (auto len = addrs[i].getLength()) {
            ret[i] = (struct sockaddr*)malloc(len);
            memcpy((struct sockaddr*)ret[i], addrs[i].get(), len);
        } else {
            ret[i] = nullptr;
        }
    }
    ret[addrs.size()] = nullptr;
    return ret;
}

#ifdef __cplusplus
}
#endif
