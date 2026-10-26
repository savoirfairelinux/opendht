// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "opendht_c.h"

#include <opendht.h>
#include <opendht/log.h>
#include <atomic>

using ValueSp = std::shared_ptr<dht::Value>;
using PrivkeySp = std::shared_ptr<dht::crypto::PrivateKey>;
using PubkeySp = std::shared_ptr<const dht::crypto::PublicKey>;
using CertSp = std::shared_ptr<dht::crypto::Certificate>;

static_assert(sizeof(dht_infohash) == sizeof(dht::InfoHash));
static_assert(alignof(dht_infohash) == alignof(dht::InfoHash));
static_assert(sizeof(dht_pkid) == sizeof(dht::PkId));
static_assert(alignof(dht_pkid) == alignof(dht::PkId));

struct CompletionGuard
{
    CompletionGuard(dht_done_cb callback, void* data)
        : callback(callback)
        , data(data)
    {}
    ~CompletionGuard() { finish(false); }
    void finish(bool ok)
    {
        if (!finished.exchange(true) && callback)
            callback(ok, data);
    }
    dht_done_cb callback;
    void* data;
    std::atomic_bool finished {false};
};

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>

const char*
dht_version()
{
    return dht::version();
}

// dht::InfoHash

inline dht_infohash
dht_infohash_to_c(const dht::InfoHash& h)
{
    dht_infohash ret;
    *reinterpret_cast<dht::InfoHash*>(&ret) = h;
    return ret;
}

inline dht_pkid
dht_pkid_to_c(const dht::PkId& h)
{
    dht_pkid ret;
    *reinterpret_cast<dht::PkId*>(&ret) = h;
    return ret;
}

const char*
dht_infohash_print(const dht_infohash* h)
{
    return reinterpret_cast<const dht::InfoHash*>(h)->to_c_str();
}

void
dht_infohash_zero(dht_infohash* h)
{
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash {};
}

void
dht_infohash_random(dht_infohash* h)
{
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash::getRandom();
}

void
dht_infohash_get(dht_infohash* h, const uint8_t* dat, size_t dat_size)
{
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash::get(dat, dat_size);
}

void
dht_infohash_get_from_string(dht_infohash* h, const char* dat)
{
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash::get((const uint8_t*) dat, (size_t) strlen(dat));
}

bool
dht_infohash_is_zero(const dht_infohash* h)
{
    return !static_cast<bool>(*reinterpret_cast<const dht::InfoHash*>(h));
}

void
dht_infohash_from_hex(dht_infohash* h, const char* dat)
{
    *h = dht_infohash_to_c(dht::InfoHash(std::string_view(dat, HASH_LEN * 2)));
}

void
dht_infohash_from_hex_null(dht_infohash* h, const char* dat)
{
    *h = dht_infohash_to_c(dht::InfoHash(std::string_view(dat)));
}

const char*
dht_pkid_print(const dht_pkid* h)
{
    return reinterpret_cast<const dht::PkId*>(h)->to_c_str();
}

// dht::Blob
void
dht_blob_delete(dht_blob* data)
{
    delete reinterpret_cast<dht::Blob*>(data);
}

dht_data_view
dht_blob_get_data(const dht_blob* data)
{
    dht_data_view view;
    view.data = reinterpret_cast<const dht::Blob*>(data)->data();
    view.size = reinterpret_cast<const dht::Blob*>(data)->size();
    return view;
}

// dht::Value
dht_data_view
dht_value_get_data(const dht_value* data)
{
    const ValueSp& vsp(*reinterpret_cast<const ValueSp*>(data));
    dht_data_view view;
    view.data = vsp->data.data();
    view.size = vsp->data.size();
    return view;
}

dht_value_id
dht_value_get_id(const dht_value* data)
{
    const ValueSp& vsp(*reinterpret_cast<const ValueSp*>(data));
    return vsp->id;
}

dht_publickey*
dht_value_get_owner(const dht_value* data)
{
    const ValueSp& vsp(*reinterpret_cast<const ValueSp*>(data));
    return vsp->owner ? reinterpret_cast<dht_publickey*>(new PubkeySp(vsp->owner)) : nullptr;
}

dht_infohash
dht_value_get_recipient(const dht_value* data)
{
    const ValueSp& vsp(*reinterpret_cast<const ValueSp*>(data));
    return dht_infohash_to_c(vsp->recipient);
}

const char*
dht_value_get_user_type(const dht_value* data)
{
    const ValueSp& vsp(*reinterpret_cast<const ValueSp*>(data));
    return vsp->user_type.c_str();
}

void
dht_value_set_user_type(dht_value* data, const char* user_type)
{
    (*reinterpret_cast<ValueSp*>(data))->user_type = user_type;
}

uint16_t
dht_value_get_type(const dht_value* value)
{
    return (*reinterpret_cast<const ValueSp*>(value))->type;
}
void
dht_value_set_type(dht_value* value, uint16_t type)
{
    (*reinterpret_cast<ValueSp*>(value))->type = type;
}
uint16_t
dht_value_get_seq(const dht_value* value)
{
    return (*reinterpret_cast<const ValueSp*>(value))->seq;
}
void
dht_value_set_seq(dht_value* value, uint16_t seq)
{
    (*reinterpret_cast<ValueSp*>(value))->seq = seq;
}
unsigned
dht_value_get_priority(const dht_value* value)
{
    return (*reinterpret_cast<const ValueSp*>(value))->priority;
}
void
dht_value_set_priority(dht_value* value, unsigned priority)
{
    (*reinterpret_cast<ValueSp*>(value))->priority = priority;
}
const char*
dht_value_get_push_type(const dht_value* value)
{
    return (*reinterpret_cast<const ValueSp*>(value))->pushType.c_str();
}
void
dht_value_set_push_type(dht_value* value, const char* push_type)
{
    (*reinterpret_cast<ValueSp*>(value))->pushType = push_type;
}

dht_value*
dht_value_with_id_new(const uint8_t* data, size_t size, uint64_t value_id)
{
    return reinterpret_cast<dht_value*>(
        new ValueSp(std::make_shared<dht::Value>(dht::ValueType::USER_DATA.id, data, size, value_id)));
}

dht_value*
dht_value_new(const uint8_t* data, size_t size)
{
    return dht_value_with_id_new(data, size, 0);
}

dht_value*
dht_value_new_from_string(const char* str)
{
    ValueSp value = std::make_shared<dht::Value>((const uint8_t*) str, strlen(str));
    value->user_type = "text/plain";
    return reinterpret_cast<dht_value*>(new ValueSp(std::move(value)));
}

dht_value*
dht_value_ref(const dht_value* v)
{
    return reinterpret_cast<dht_value*>(new ValueSp(*reinterpret_cast<const ValueSp*>(v)));
}

dht_value*
dht_value_copy(const dht_value* value)
{
    try {
        const auto& source = **reinterpret_cast<const ValueSp*>(value);
        auto copy = std::make_shared<dht::Value>();
        copy->id = source.id;
        copy->owner = source.owner;
        copy->recipient = source.recipient;
        copy->type = source.type;
        copy->data = source.data;
        copy->user_type = source.user_type;
        copy->seq = source.seq;
        copy->signature = source.signature;
        copy->cypher = source.cypher;
        copy->priority = source.priority;
        copy->pushType = source.pushType;
        return reinterpret_cast<dht_value*>(new ValueSp(std::move(copy)));
    } catch (...) {
        return nullptr;
    }
}

void
dht_value_unref(dht_value* v)
{
    delete reinterpret_cast<ValueSp*>(v);
}

// dht::crypto::PublicKey
dht_publickey*
dht_publickey_import(const uint8_t* dat, size_t dat_size)
{
    try {
        return reinterpret_cast<dht_publickey*>(
            new PubkeySp(std::make_shared<const dht::crypto::PublicKey>(dat, dat_size)));
    } catch (...) {
        return nullptr;
    }
}

void
dht_publickey_delete(dht_publickey* pk)
{
    delete reinterpret_cast<PubkeySp*>(pk);
}

int
dht_publickey_export(const dht_publickey* pk, char* out, size_t* outlen)
{
    const auto& pkey = *reinterpret_cast<const PubkeySp*>(pk);
    return pkey->pack((uint8_t*) out, outlen);
}

dht_blob*
dht_publickey_export_blob(const dht_publickey* pk)
{
    try {
        auto data = std::make_unique<dht::Blob>();
        (*reinterpret_cast<const PubkeySp*>(pk))->pack(*data);
        return reinterpret_cast<dht_blob*>(data.release());
    } catch (...) {
        return nullptr;
    }
}

int
dht_publickey_unpack(dht_publickey* pk, const uint8_t* data, size_t size)
{
    try {
        *reinterpret_cast<PubkeySp*>(pk) = std::make_shared<const dht::crypto::PublicKey>(data, size);
        return 0;
    } catch (...) {
        return EINVAL;
    }
}

dht_infohash
dht_publickey_get_id(const dht_publickey* pk)
{
    const auto& pkey = *reinterpret_cast<const PubkeySp*>(pk);
    return dht_infohash_to_c(pkey->getId());
}

dht_pkid
dht_publickey_get_long_id(const dht_publickey* pk)
{
    const auto& pkey = *reinterpret_cast<const PubkeySp*>(pk);
    return dht_pkid_to_c(pkey->getLongId());
}

bool
dht_publickey_check_signature(
    const dht_publickey* pk, const char* data, size_t data_size, const char* signature, size_t signature_size)
{
    const auto& pkey = *reinterpret_cast<const PubkeySp*>(pk);
    return pkey->checkSignature((const uint8_t*) data, data_size, (const uint8_t*) signature, signature_size);
}

dht_blob*
dht_publickey_encrypt(const dht_publickey* pk, const char* data, size_t data_size)
{
    const auto& pkey = *reinterpret_cast<const PubkeySp*>(pk);
    try {
        auto rdata = std::make_unique<dht::Blob>();
        *rdata = pkey->encrypt((const uint8_t*) data, data_size);
        return (dht_blob*) rdata.release();
    } catch (...) {
        return nullptr;
    }
}

// dht::crypto::PrivateKey
dht_privatekey*
dht_privatekey_generate(unsigned key_length_bits)
{
    if (key_length_bits == 0)
        key_length_bits = 4096;
    try {
        return reinterpret_cast<dht_privatekey*>(new PrivkeySp(
            std::make_shared<dht::crypto::PrivateKey>(dht::crypto::PrivateKey::generate(key_length_bits))));
    } catch (...) {
        return nullptr;
    }
}

dht_privatekey*
dht_privatekey_import(const uint8_t* dat, size_t dat_size, const char* password)
{
    try {
        return reinterpret_cast<dht_privatekey*>(
            new PrivkeySp(std::make_shared<dht::crypto::PrivateKey>(dat, dat_size, password)));
    } catch (...) {
        return nullptr;
    }
}

int
dht_privatekey_export(const dht_privatekey* k, char* out, size_t* out_size, const char* password)
{
    if (!out or !out_size or !*out_size)
        return -1;
    const auto& key = *reinterpret_cast<const PrivkeySp*>(k);
    try {
        return key->serialize((uint8_t*) out, out_size, password ? password : "");
    } catch (...) {
        return -1;
    }
}

dht_privatekey*
dht_privatekey_generate_ec(void)
{
    try {
        return reinterpret_cast<dht_privatekey*>(
            new PrivkeySp(std::make_shared<dht::crypto::PrivateKey>(dht::crypto::PrivateKey::generateEC())));
    } catch (...) {
        return nullptr;
    }
}

dht_blob*
dht_privatekey_export_blob(const dht_privatekey* key, const char* password)
{
    try {
        return reinterpret_cast<dht_blob*>(
            new dht::Blob((*reinterpret_cast<const PrivkeySp*>(key))->serialize(password ? password : "")));
    } catch (...) {
        return nullptr;
    }
}

dht_blob*
dht_privatekey_sign(const dht_privatekey* key, const uint8_t* data, size_t size)
{
    try {
        return reinterpret_cast<dht_blob*>(new dht::Blob((*reinterpret_cast<const PrivkeySp*>(key))->sign(data, size)));
    } catch (...) {
        return nullptr;
    }
}

dht_publickey*
dht_privatekey_get_publickey(const dht_privatekey* k)
{
    const auto& key = *reinterpret_cast<const PrivkeySp*>(k);
    return reinterpret_cast<dht_publickey*>(new PubkeySp(key->getSharedPublicKey()));
}

dht_blob*
dht_privatekey_decrypt(const dht_privatekey* k, const char* data, size_t data_size)
{
    const auto& key = *reinterpret_cast<const PrivkeySp*>(k);
    try {
        auto rdata = std::make_unique<dht::Blob>();
        *rdata = key->decrypt((const uint8_t*) data, data_size);
        return (dht_blob*) rdata.release();
    } catch (...) {
        return nullptr;
    }
}

void
dht_privatekey_delete(dht_privatekey* pk)
{
    delete reinterpret_cast<PrivkeySp*>(pk);
}

// dht::crypto::Certificate
dht_certificate*
dht_certificate_import(const uint8_t* dat, size_t dat_size)
{
    try {
        return reinterpret_cast<dht_certificate*>(new CertSp(std::make_shared<dht::crypto::Certificate>(dat, dat_size)));
    } catch (...) {
        return nullptr;
    }
}

dht_blob*
dht_certificate_export(const dht_certificate* certificate)
{
    try {
        return reinterpret_cast<dht_blob*>(new dht::Blob((*reinterpret_cast<const CertSp*>(certificate))->getPacked()));
    } catch (...) {
        return nullptr;
    }
}

dht_certificate*
dht_certificate_ref(const dht_certificate* certificate)
{
    return certificate ? reinterpret_cast<dht_certificate*>(new CertSp(*reinterpret_cast<const CertSp*>(certificate)))
                       : nullptr;
}

void
dht_certificate_delete(dht_certificate* c)
{
    delete reinterpret_cast<CertSp*>(c);
}

dht_infohash
dht_certificate_get_id(const dht_certificate* c)
{
    const auto& cert = *reinterpret_cast<const CertSp*>(c);
    return dht_infohash_to_c(cert->getId());
}

dht_pkid
dht_certificate_get_long_id(const dht_certificate* c)
{
    const auto& cert = *reinterpret_cast<const CertSp*>(c);
    return dht_pkid_to_c(cert->getLongId());
}

dht_publickey*
dht_certificate_get_publickey(const dht_certificate* c)
{
    const auto& cert = *reinterpret_cast<const CertSp*>(c);
    return reinterpret_cast<dht_publickey*>(new PubkeySp(cert->getSharedPublicKey()));
}

#ifdef __cplusplus
} // extern "C"
// Function with internal C++ linkage
#endif

// dht::crypto::Identity
inline dht::crypto::Identity
dht_identity_from_c(const dht_identity* cid)
{
    dht::crypto::Identity id {};
    if (cid and cid->privatekey)
        id.first = *reinterpret_cast<const PrivkeySp*>(cid->privatekey);
    if (cid and cid->certificate)
        id.second = *reinterpret_cast<const CertSp*>(cid->certificate);
    return id;
}

inline dht_identity
dht_identity_to_c(const dht::crypto::Identity& id)
{
    dht_identity cid {};
    auto key = id.first ? std::make_unique<PrivkeySp>(id.first) : nullptr;
    auto certificate = id.second ? std::make_unique<CertSp>(id.second) : nullptr;
    cid.privatekey = reinterpret_cast<dht_privatekey*>(key.release());
    cid.certificate = reinterpret_cast<dht_certificate*>(certificate.release());
    return cid;
}

#ifdef __cplusplus
extern "C" {
#endif

OPENDHT_C_PUBLIC dht_identity
dht_identity_generate(const char* common_name, const dht_identity* ca)
{
    try {
        return dht_identity_to_c(
            dht::crypto::generateIdentity(common_name ? common_name : "dhtnode", dht_identity_from_c(ca)));
    } catch (...) {
        return {};
    }
}

OPENDHT_C_PUBLIC void
dht_identity_delete(dht_identity* id)
{
    if (id->certificate) {
        dht_certificate_delete(id->certificate);
        id->certificate = NULL;
    }
    if (id->privatekey) {
        dht_privatekey_delete(id->privatekey);
        id->privatekey = NULL;
    }
}

dht_identity
dht_identity_generate_ec(const char* common_name, const dht_identity* ca)
{
    try {
        return dht_identity_to_c(
            dht::crypto::generateEcIdentity(common_name ? common_name : "dhtnode", dht_identity_from_c(ca)));
    } catch (...) {
        return {};
    }
}

// config
void
dht_runner_config_default(dht_runner_config* config)
{
    memset(config, 0, sizeof(dht_runner_config));
    config->threaded = true;
}

// dht::DhtRunner
dht_runner*
dht_runner_new(void)
{
    return reinterpret_cast<dht_runner*>(new dht::DhtRunner);
}

void
dht_runner_delete(dht_runner* runner)
{
    delete reinterpret_cast<dht::DhtRunner*>(runner);
}

int
dht_runner_loop(dht_runner* runner)
{
    try {
        reinterpret_cast<dht::DhtRunner*>(runner)->loop();
        return 0;
    } catch (...) {
        return EINVAL;
    }
}

int
dht_runner_join(dht_runner* runner)
{
    try {
        reinterpret_cast<dht::DhtRunner*>(runner)->join();
        return 0;
    } catch (...) {
        return EDEADLK;
    }
}

int
dht_runner_run(dht_runner* r, in_port_t port)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    try {
        runner->run(port, {}, true);
    } catch (...) {
        return ENOTCONN;
    }
    return 0;
}
}

static dht::DhtRunner::Config
config_from_c(const dht_runner_config* conf)
{
    dht::DhtRunner::Config config;
    config.dht_config.node_config.is_bootstrap = conf->dht_config.node_config.is_bootstrap;
    config.dht_config.node_config.maintain_storage = conf->dht_config.node_config.maintain_storage;
    config.dht_config.node_config.node_id = *reinterpret_cast<const dht::InfoHash*>(
        &conf->dht_config.node_config.node_id);
    config.dht_config.node_config.network = conf->dht_config.node_config.network;
    config.dht_config.node_config.persist_path = conf->dht_config.node_config.persist_path
                                                     ? std::string(conf->dht_config.node_config.persist_path)
                                                     : std::string {};

    if (conf->dht_config.id.privatekey)
        config.dht_config.id.first = *reinterpret_cast<const PrivkeySp*>(conf->dht_config.id.privatekey);

    if (conf->dht_config.id.certificate)
        config.dht_config.id.second = *reinterpret_cast<const CertSp*>(conf->dht_config.id.certificate);

    config.threaded = conf->threaded;
    config.proxy_server = conf->proxy_server ? std::string(conf->proxy_server) : std::string {};
    config.push_node_id = conf->push_node_id ? std::string(conf->push_node_id) : std::string {};
    config.push_token = conf->push_token ? std::string(conf->push_token) : std::string {};
    config.push_topic = conf->push_topic ? std::string(conf->push_topic) : std::string {};
    config.push_platform = conf->push_platform ? std::string(conf->push_platform) : std::string {};
    config.proxy_user_agent = conf->proxy_user_agent ? std::string(conf->proxy_user_agent) : std::string {};
    config.peer_discovery = conf->peer_discovery;
    config.peer_publish = conf->peer_publish;
    if (conf->server_ca)
        config.server_ca = *reinterpret_cast<const CertSp*>(conf->server_ca);
    config.client_identity = dht_identity_from_c(&conf->client_identity);
    return config;
}

extern "C" {

int
dht_runner_run_config(dht_runner* runner, in_port_t port, const dht_runner_config* config)
{
    return dht_runner_run_bind(runner, nullptr, nullptr, port, config, nullptr);
}

int
dht_runner_run_bind(dht_runner* runner,
                    const char* ipv4,
                    const char* ipv6,
                    in_port_t port,
                    const dht_runner_config* conf,
                    const dht_runner_context* callbacks)
{
    try {
        auto lifetime = callbacks ? std::shared_ptr<void>(callbacks->user_data,
                                                          [release = callbacks->released_cb](void* data) {
                                                              if (release)
                                                                  release(data);
                                                          })
                                  : std::shared_ptr<void> {};
        auto config = config_from_c(conf);
        dht::DhtRunner::Context context;
        if (conf->log) {
            context.logger = dht::log::getStdLogger();
        }
        if (callbacks) {
            if (callbacks->status_cb) {
                context.statusChangedCallback = [lifetime, cb = callbacks->status_cb](dht::NodeStatus ipv4,
                                                                                      dht::NodeStatus ipv6) {
                    cb(static_cast<int>(ipv4), static_cast<int>(ipv6), lifetime.get());
                };
            }
            if (callbacks->certificate_store_cb) {
                context.certificateStore = [lifetime, cb = callbacks->certificate_store_cb](const dht::PkId& id) {
                    std::vector<std::shared_ptr<dht::crypto::Certificate>> found;
                    auto emit = [](const dht_certificate* certificate, void* data) {
                        if (certificate)
                            static_cast<decltype(found)*>(data)->push_back(
                                *reinterpret_cast<const CertSp*>(certificate));
                    };
                    auto hash = dht_pkid_to_c(id);
                    cb(&hash, emit, &found, lifetime.get());
                    return found;
                };
            }
        }
        auto service = std::to_string(port);
        reinterpret_cast<dht::DhtRunner*>(runner)
            ->run(ipv4 ? ipv4 : "0.0.0.0", ipv6 ? ipv6 : "::", service.c_str(), config, std::move(context));
    } catch (...) {
        return ENOTCONN;
    }
    return 0;
}

int
dht_runner_connectivity_changed(dht_runner* runner)
{
    try {
        reinterpret_cast<dht::DhtRunner*>(runner)->connectivityChanged();
        return 0;
    } catch (...) {
        return EINVAL;
    }
}

int
dht_runner_register_type(dht_runner* runner, uint16_t id, const char* name, uint64_t expiration_seconds, bool insecure)
{
    if (!dht_runner_is_running(runner) || !name
        || expiration_seconds
               > static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(dht::duration::max()).count()))
        return EINVAL;
    try {
        dht::ValueType type(id, name, std::chrono::seconds(expiration_seconds));
        if (insecure)
            reinterpret_cast<dht::DhtRunner*>(runner)->registerInsecureType(type);
        else
            reinterpret_cast<dht::DhtRunner*>(runner)->registerType(type);
        return 0;
    } catch (...) {
        return EINVAL;
    }
}

dht_publickey*
dht_runner_get_publickey(const dht_runner* runner)
{
    try {
        auto key = reinterpret_cast<const dht::DhtRunner*>(runner)->getPublicKey();
        return key ? reinterpret_cast<dht_publickey*>(new PubkeySp(std::move(key))) : nullptr;
    } catch (...) {
        return nullptr;
    }
}

int
dht_runner_register_certificate(dht_runner* runner, const dht_certificate* certificate)
{
    if (!dht_runner_is_running(runner))
        return ENOTCONN;
    try {
        reinterpret_cast<dht::DhtRunner*>(runner)->registerCertificate(*reinterpret_cast<const CertSp*>(certificate));
        return 0;
    } catch (...) {
        return EINVAL;
    }
}

void
dht_runner_ping(dht_runner* r, struct sockaddr* addr, socklen_t addr_len, dht_done_cb done_cb, void* cb_user_data)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto guard = std::make_shared<CompletionGuard>(done_cb, cb_user_data);
    try {
        runner->bootstrap(dht::SockAddr(addr, addr_len), [guard](bool ok) { guard->finish(ok); });
    } catch (...) {
        guard->finish(false);
    }
}

void
dht_runner_bootstrap(dht_runner* r, const char* host, const char* service)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    if (service)
        runner->bootstrap(host, service);
    else
        runner->bootstrap(host);
}

void
dht_runner_get(dht_runner* r, const dht_infohash* h, dht_get_cb cb, dht_done_cb done_cb, void* cb_user_data)
{
    dht_runner_get_filtered(r, h, nullptr, cb, done_cb, cb_user_data);
}

void
dht_runner_get_filtered(
    dht_runner* r, const dht_infohash* h, const char* where, dht_get_cb cb, dht_done_cb done_cb, void* cb_user_data)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto guard = std::make_shared<CompletionGuard>(done_cb, cb_user_data);
    try {
        runner->get(
            *hash,
            [cb, cb_user_data, guard](std::shared_ptr<dht::Value> value) {
                return cb ? cb(reinterpret_cast<const dht_value*>(&value), cb_user_data) : true;
            },
            [guard](bool ok) { guard->finish(ok); },
            {},
            where ? dht::Where(where) : dht::Where {});
    } catch (...) {
        guard->finish(false);
    }
}

struct ScopeGuardCb
{
    ScopeGuardCb(dht_shutdown_cb cb, void* data)
        : onDestroy(cb)
        , userData(data)
    {}

    ~ScopeGuardCb()
    {
        if (onDestroy)
            onDestroy((void*) userData);
    }

private:
    const dht_shutdown_cb onDestroy;
    void const* userData;
};

dht_op_token*
dht_runner_listen(dht_runner* r, const dht_infohash* h, dht_value_cb cb, dht_shutdown_cb done_cb, void* cb_user_data)
{
    return dht_runner_listen_filtered(r, h, nullptr, cb, done_cb, cb_user_data);
}

dht_op_token*
dht_runner_listen_filtered(dht_runner* r,
                           const dht_infohash* h,
                           const char* where,
                           dht_value_cb cb,
                           dht_shutdown_cb done_cb,
                           void* cb_user_data)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto guard = std::make_shared<ScopeGuardCb>(done_cb, cb_user_data);
    try {
        auto fret = std::make_unique<std::future<size_t>>();
        *fret = runner->listen(
            *hash,
            [cb, cb_user_data, guard](const std::vector<std::shared_ptr<dht::Value>>& values, bool expired) {
                for (const auto& value : values) {
                    if (cb && not cb(reinterpret_cast<const dht_value*>(&value), expired, cb_user_data))
                        return false;
                }
                return true;
            },
            {},
            where ? dht::Where(where) : dht::Where {});
        return reinterpret_cast<dht_op_token*>(fret.release());
    } catch (...) {
        return nullptr;
    }
}

void
dht_runner_cancel_listen(dht_runner* r, const dht_infohash* h, dht_op_token* t)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto token = reinterpret_cast<std::future<size_t>*>(t);
    runner->cancelListen(*hash, std::move(*token));
}

void
dht_op_token_delete(dht_op_token* token)
{
    delete reinterpret_cast<std::future<size_t>*>(token);
}

void
dht_runner_query(
    dht_runner* r, const dht_infohash* h, const char* query, dht_query_cb cb, dht_done_cb done_cb, void* user_data)
{
    auto guard = std::make_shared<CompletionGuard>(done_cb, user_data);
    try {
        reinterpret_cast<dht::DhtRunner*>(r)->query(
            *reinterpret_cast<const dht::InfoHash*>(h),
            [guard, cb, user_data](const std::vector<std::shared_ptr<dht::FieldValueIndex>>& results) {
                for (const auto& index : results) {
                    dht_query_result result {};
                    dht::Blob user_type;
                    for (const auto& entry : index->index) {
                        switch (entry.first) {
                        case dht::Value::Field::Id:
                            result.fields |= DHT_FIELD_ID;
                            result.id = entry.second.getInt();
                            break;
                        case dht::Value::Field::ValueType:
                            result.fields |= DHT_FIELD_TYPE;
                            result.value_type = entry.second.getInt();
                            break;
                        case dht::Value::Field::SeqNum:
                            result.fields |= DHT_FIELD_SEQ;
                            result.seq = entry.second.getInt();
                            break;
                        case dht::Value::Field::OwnerPk:
                            result.fields |= DHT_FIELD_OWNER;
                            result.owner = dht_infohash_to_c(entry.second.getHash());
                            break;
                        case dht::Value::Field::UserType:
                            result.fields |= DHT_FIELD_USER_TYPE;
                            user_type = entry.second.getBlob();
                            result.user_type = {user_type.data(), user_type.size()};
                            break;
                        default:
                            break;
                        }
                    }
                    if (cb && !cb(&result, user_data))
                        return false;
                }
                return true;
            },
            [guard](bool ok) { guard->finish(ok); },
            dht::Query(query ? query : ""));
    } catch (...) {
        guard->finish(false);
    }
}

void
dht_runner_find_certificate(
    dht_runner* runner, const dht_pkid* id, dht_certificate_cb callback, dht_shutdown_cb released_cb, void* user_data)
{
    auto guard = std::make_shared<ScopeGuardCb>(released_cb, user_data);
    try {
        reinterpret_cast<dht::DhtRunner*>(runner)->findCertificate(
            *reinterpret_cast<const dht::PkId*>(id),
            [guard, callback, user_data](const std::shared_ptr<dht::crypto::Certificate>& certificate) {
                if (callback)
                    callback(certificate ? reinterpret_cast<const dht_certificate*>(&certificate) : nullptr, user_data);
            });
    } catch (...) {
    }
}

void
dht_runner_put(
    dht_runner* r, const dht_infohash* h, const dht_value* v, dht_done_cb done_cb, void* cb_user_data, bool permanent)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto value = reinterpret_cast<const ValueSp*>(v);
    auto guard = std::make_shared<CompletionGuard>(done_cb, cb_user_data);
    try {
        runner->put(*hash, *value, [guard](bool ok) { guard->finish(ok); }, dht::time_point::max(), permanent);
    } catch (...) {
        guard->finish(false);
    }
}

void
dht_runner_put_signed(
    dht_runner* r, const dht_infohash* h, const dht_value* v, dht_done_cb done_cb, void* cb_user_data, bool permanent)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto value = reinterpret_cast<const ValueSp*>(v);
    auto guard = std::make_shared<CompletionGuard>(done_cb, cb_user_data);
    try {
        runner->putSigned(*hash, *value, [guard](bool ok) { guard->finish(ok); }, permanent);
    } catch (...) {
        guard->finish(false);
    }
}

void
dht_runner_put_encrypted(dht_runner* r,
                         const dht_infohash* h,
                         const dht_pkid* to,
                         const dht_value* v,
                         dht_done_cb done_cb,
                         void* cb_user_data,
                         bool permanent)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    auto toHash = reinterpret_cast<const dht::PkId*>(to);
    auto value = reinterpret_cast<const ValueSp*>(v);
    auto guard = std::make_shared<CompletionGuard>(done_cb, cb_user_data);
    try {
        runner->putEncrypted(*hash, *toHash, *value, [guard](bool ok) { guard->finish(ok); }, permanent);
    } catch (...) {
        guard->finish(false);
    }
}

void
dht_runner_cancel_put(dht_runner* r, const dht_infohash* h, dht_value_id value_id)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    runner->cancelPut(*hash, value_id);
}

void
dht_runner_shutdown(dht_runner* r, dht_shutdown_cb done_cb, void* cb_user_data)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto guard = std::make_shared<ScopeGuardCb>(done_cb, cb_user_data);
    runner->shutdown([guard]() {});
}

bool
dht_runner_is_running(const dht_runner* r)
{
    if (not r)
        return false;
    auto runner = reinterpret_cast<const dht::DhtRunner*>(r);
    return runner->isRunning();
}

in_port_t
dht_runner_get_bound_port(const dht_runner* r, sa_family_t af)
{
    auto runner = reinterpret_cast<const dht::DhtRunner*>(r);
    return runner->getBoundPort(af);
}

dht_infohash
dht_runner_get_node_id(const dht_runner* r)
{
    auto runner = reinterpret_cast<const dht::DhtRunner*>(r);
    dht_infohash ret;
    *reinterpret_cast<dht::InfoHash*>(&ret) = runner->getNodeId();
    return ret;
}

dht_infohash
dht_runner_get_id(const dht_runner* r)
{
    auto runner = reinterpret_cast<const dht::DhtRunner*>(r);
    dht_infohash ret;
    *reinterpret_cast<dht::InfoHash*>(&ret) = runner->getId();
    return ret;
}

struct sockaddr**
dht_runner_get_public_address(const dht_runner* r)
{
    auto runner = reinterpret_cast<const dht::DhtRunner*>(r);
    auto addrs = const_cast<dht::DhtRunner*>(runner)->getPublicAddress();
    if (addrs.empty())
        return nullptr;
    auto ret = (struct sockaddr**) malloc(sizeof(struct sockaddr*) * (addrs.size() + 1));
    if (!ret)
        return nullptr;
    for (size_t i = 0; i < addrs.size(); i++)
        ret[i] = addrs[i].release();
    ret[addrs.size()] = nullptr;
    return ret;
}

void
dht_sockaddr_array_delete(struct sockaddr** addresses)
{
    if (addresses) {
        for (auto current = addresses; *current; ++current)
            free(*current);
        free(addresses);
    }
}

int
dht_runner_set_push_notification_token(dht_runner* runner, const char* value)
{
    try {
        reinterpret_cast<dht::DhtRunner*>(runner)->setPushNotificationToken(value ? value : "");
        return 0;
    } catch (...) {
        return EINVAL;
    }
}
int
dht_runner_set_push_notification_topic(dht_runner* runner, const char* value)
{
    try {
        reinterpret_cast<dht::DhtRunner*>(runner)->setPushNotificationTopic(value ? value : "");
        return 0;
    } catch (...) {
        return EINVAL;
    }
}
int
dht_runner_set_push_notification_platform(dht_runner* runner, const char* value)
{
    try {
        reinterpret_cast<dht::DhtRunner*>(runner)->setPushNotificationPlatform(value ? value : "");
        return 0;
    } catch (...) {
        return EINVAL;
    }
}

dht_push_token*
dht_runner_push_notification_received(dht_runner* runner,
                                      const char* const* keys,
                                      const char* const* values,
                                      size_t count)
{
    try {
        std::map<std::string, std::string> data;
        for (size_t index = 0; index < count; ++index)
            data.emplace(keys[index], values[index]);
        return reinterpret_cast<dht_push_token*>(new std::future<dht::PushNotificationResult>(
            reinterpret_cast<dht::DhtRunner*>(runner)->pushNotificationReceived(data)));
    } catch (...) {
        return nullptr;
    }
}

int
dht_push_token_poll(dht_push_token* token, int* result)
{
    if (!token || !result)
        return EINVAL;
    try {
        auto future = reinterpret_cast<std::future<dht::PushNotificationResult>*>(token);
        if (future->wait_for(std::chrono::seconds(0)) != std::future_status::ready)
            return EAGAIN;
        *result = static_cast<int>(future->get());
        return 0;
    } catch (...) {
        return EIO;
    }
}

void
dht_push_token_delete(dht_push_token* token)
{
    delete reinterpret_cast<std::future<dht::PushNotificationResult>*>(token);
}

#ifdef __cplusplus
}
#endif
