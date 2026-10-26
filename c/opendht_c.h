// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <opendht/def.h>

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef uint16_t sa_family_t;
typedef uint16_t in_port_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

// Non-owning data view
struct OPENDHT_C_PUBLIC dht_data_view
{
    const uint8_t* data;
    size_t size;
};
typedef struct dht_data_view dht_data_view;

OPENDHT_C_PUBLIC const char* dht_version(void);

// dht::Blob
struct OPENDHT_C_PUBLIC dht_blob;
typedef struct dht_blob dht_blob;
OPENDHT_C_PUBLIC dht_data_view dht_blob_get_data(const dht_blob* data);
OPENDHT_C_PUBLIC void dht_blob_delete(dht_blob* data);

// dht::InfoHash
struct OPENDHT_C_PUBLIC dht_infohash
{
    uint8_t d[HASH_LEN];
};
typedef struct dht_infohash dht_infohash;
OPENDHT_C_PUBLIC void dht_infohash_zero(dht_infohash* h);
OPENDHT_C_PUBLIC void dht_infohash_random(dht_infohash* h);
OPENDHT_C_PUBLIC void dht_infohash_from_hex(dht_infohash* h, const char* dat);
OPENDHT_C_PUBLIC void dht_infohash_from_hex_null(dht_infohash* h, const char* dat);
OPENDHT_C_PUBLIC void dht_infohash_get(dht_infohash* h, const uint8_t* dat, size_t dat_size);
OPENDHT_C_PUBLIC void dht_infohash_get_from_string(dht_infohash* h, const char* str);
OPENDHT_C_PUBLIC const char* dht_infohash_print(const dht_infohash* h);
OPENDHT_C_PUBLIC bool dht_infohash_is_zero(const dht_infohash* h);

// dht::PkId
struct OPENDHT_C_PUBLIC dht_pkid
{
    uint8_t d[32];
};
typedef struct dht_pkid dht_pkid;
OPENDHT_C_PUBLIC const char* dht_pkid_print(const dht_pkid* h);

// dht::crypto::PublicKey
struct OPENDHT_C_PUBLIC dht_publickey;
typedef struct dht_publickey dht_publickey;
OPENDHT_C_PUBLIC dht_publickey* dht_publickey_import(const uint8_t* dat, size_t dat_size);
OPENDHT_C_PUBLIC void dht_publickey_delete(dht_publickey* pk);
OPENDHT_C_PUBLIC int dht_publickey_export(const dht_publickey* pk, char* out, size_t* out_size);
OPENDHT_C_PUBLIC dht_blob* dht_publickey_export_blob(const dht_publickey* pk);
OPENDHT_C_PUBLIC int dht_publickey_unpack(dht_publickey* pk, const uint8_t* data, size_t size);
OPENDHT_C_PUBLIC dht_infohash dht_publickey_get_id(const dht_publickey* pk);
OPENDHT_C_PUBLIC dht_pkid dht_publickey_get_long_id(const dht_publickey* pk);
OPENDHT_C_PUBLIC bool dht_publickey_check_signature(
    const dht_publickey* pk, const char* data, size_t data_size, const char* signature, size_t signature_size);
OPENDHT_C_PUBLIC dht_blob* dht_publickey_encrypt(const dht_publickey* pk, const char* data, size_t data_size);

// dht::crypto::PrivateKey
struct OPENDHT_C_PUBLIC dht_privatekey;
typedef struct dht_privatekey dht_privatekey;
OPENDHT_C_PUBLIC dht_privatekey* dht_privatekey_generate(unsigned key_length_bits);
OPENDHT_C_PUBLIC dht_privatekey* dht_privatekey_generate_ec(void);
OPENDHT_C_PUBLIC dht_privatekey* dht_privatekey_import(const uint8_t* dat, size_t dat_size, const char* password);
OPENDHT_C_PUBLIC int dht_privatekey_export(const dht_privatekey*, char* out, size_t* out_size, const char* password);
OPENDHT_C_PUBLIC dht_blob* dht_privatekey_export_blob(const dht_privatekey*, const char* password);
OPENDHT_C_PUBLIC dht_blob* dht_privatekey_sign(const dht_privatekey*, const uint8_t* data, size_t size);
OPENDHT_C_PUBLIC dht_publickey* dht_privatekey_get_publickey(const dht_privatekey*);
OPENDHT_C_PUBLIC dht_blob* dht_privatekey_decrypt(const dht_privatekey*, const char* data, size_t data_size);
OPENDHT_C_PUBLIC void dht_privatekey_delete(dht_privatekey*);

// dht::crypto::Certificate
struct OPENDHT_C_PUBLIC dht_certificate;
typedef struct dht_certificate dht_certificate;
OPENDHT_C_PUBLIC dht_certificate* dht_certificate_import(const uint8_t* dat, size_t dat_size);
OPENDHT_C_PUBLIC dht_blob* dht_certificate_export(const dht_certificate* certificate);
OPENDHT_C_PUBLIC dht_certificate* dht_certificate_ref(const dht_certificate* certificate);
OPENDHT_C_PUBLIC dht_infohash dht_certificate_get_id(const dht_certificate*);
OPENDHT_C_PUBLIC dht_pkid dht_certificate_get_long_id(const dht_certificate*);
OPENDHT_C_PUBLIC dht_publickey* dht_certificate_get_publickey(const dht_certificate*);
OPENDHT_C_PUBLIC void dht_certificate_delete(dht_certificate*);

struct OPENDHT_C_PUBLIC dht_identity
{
    dht_privatekey* privatekey;
    dht_certificate* certificate;
};
typedef struct dht_identity dht_identity;
OPENDHT_C_PUBLIC dht_identity dht_identity_generate(const char* common_name, const dht_identity* ca);
OPENDHT_C_PUBLIC dht_identity dht_identity_generate_ec(const char* common_name, const dht_identity* ca);
OPENDHT_C_PUBLIC void dht_identity_delete(dht_identity*);

// dht::Value
struct OPENDHT_C_PUBLIC dht_value;
typedef struct dht_value dht_value;
typedef uint64_t dht_value_id;
OPENDHT_C_PUBLIC dht_value* dht_value_new(const uint8_t* data, size_t size);
OPENDHT_C_PUBLIC dht_value* dht_value_with_id_new(const uint8_t* data, size_t size, uint64_t value_id);
OPENDHT_C_PUBLIC dht_value* dht_value_new_from_string(const char* str);
OPENDHT_C_PUBLIC dht_value* dht_value_ref(const dht_value*);
OPENDHT_C_PUBLIC dht_value* dht_value_copy(const dht_value*);
OPENDHT_C_PUBLIC void dht_value_unref(dht_value*);
OPENDHT_C_PUBLIC dht_data_view dht_value_get_data(const dht_value* data);
OPENDHT_C_PUBLIC dht_value_id dht_value_get_id(const dht_value* data);
OPENDHT_C_PUBLIC dht_publickey* dht_value_get_owner(const dht_value* data);
OPENDHT_C_PUBLIC dht_infohash dht_value_get_recipient(const dht_value* data);
OPENDHT_C_PUBLIC const char* dht_value_get_user_type(const dht_value* data);
OPENDHT_C_PUBLIC void dht_value_set_user_type(dht_value* data, const char* user_type);
OPENDHT_C_PUBLIC uint16_t dht_value_get_type(const dht_value* value);
OPENDHT_C_PUBLIC void dht_value_set_type(dht_value* value, uint16_t type);
OPENDHT_C_PUBLIC uint16_t dht_value_get_seq(const dht_value* value);
OPENDHT_C_PUBLIC void dht_value_set_seq(dht_value* value, uint16_t seq);
OPENDHT_C_PUBLIC unsigned dht_value_get_priority(const dht_value* value);
OPENDHT_C_PUBLIC void dht_value_set_priority(dht_value* value, unsigned priority);
OPENDHT_C_PUBLIC const char* dht_value_get_push_type(const dht_value* value);
OPENDHT_C_PUBLIC void dht_value_set_push_type(dht_value* value, const char* push_type);

// callbacks
typedef bool (*dht_get_cb)(const dht_value* value, void* user_data);
typedef bool (*dht_value_cb)(const dht_value* value, bool expired, void* user_data);
typedef void (*dht_done_cb)(bool ok, void* user_data);
typedef void (*dht_shutdown_cb)(void* user_data);
typedef void (*dht_status_cb)(int ipv4_status, int ipv6_status, void* user_data);
typedef void (*dht_certificate_cb)(const dht_certificate* certificate, void* user_data);
typedef void (*dht_certificate_store_cb)(const dht_pkid* id, dht_certificate_cb emit, void* emit_data, void* user_data);

typedef struct dht_runner_context
{
    dht_status_cb status_cb;
    dht_certificate_store_cb certificate_store_cb;
    dht_shutdown_cb released_cb;
    void* user_data;
} dht_runner_context;

enum dht_query_field {
    DHT_FIELD_ID = 1,
    DHT_FIELD_TYPE = 2,
    DHT_FIELD_SEQ = 4,
    DHT_FIELD_OWNER = 8,
    DHT_FIELD_USER_TYPE = 16
};

typedef struct dht_query_result
{
    uint32_t fields;
    uint64_t id;
    uint16_t value_type;
    uint16_t seq;
    dht_infohash owner;
    dht_data_view user_type;
} dht_query_result;
typedef bool (*dht_query_cb)(const dht_query_result* result, void* user_data);

struct dht_push_token;
typedef struct dht_push_token dht_push_token;

struct OPENDHT_C_PUBLIC dht_op_token;
typedef struct dht_op_token dht_op_token;
OPENDHT_C_PUBLIC void dht_op_token_delete(dht_op_token* token);

// config
struct OPENDHT_C_PUBLIC dht_node_config
{
    dht_infohash node_id;
    uint32_t network;
    bool is_bootstrap;
    bool maintain_storage;
    const char* persist_path;
};
typedef struct dht_node_config dht_node_config;

struct OPENDHT_C_PUBLIC dht_secure_config
{
    dht_node_config node_config;
    dht_identity id;
};
typedef struct dht_secure_config dht_secure_config;

struct OPENDHT_C_PUBLIC dht_runner_config
{
    dht_secure_config dht_config;
    bool threaded;
    const char* proxy_server;
    const char* push_node_id;
    const char* push_token;
    const char* push_topic;
    const char* push_platform;
    const char* proxy_user_agent;
    bool peer_discovery;
    bool peer_publish;
    dht_certificate* server_ca;
    dht_identity client_identity;
    bool log;
};
typedef struct dht_runner_config dht_runner_config;
OPENDHT_C_PUBLIC void dht_runner_config_default(dht_runner_config* config);

// dht::DhtRunner
struct OPENDHT_C_PUBLIC dht_runner;
typedef struct dht_runner dht_runner;
OPENDHT_C_PUBLIC dht_runner* dht_runner_new(void);
OPENDHT_C_PUBLIC void dht_runner_delete(dht_runner* runner);
OPENDHT_C_PUBLIC int dht_runner_loop(dht_runner* runner);
OPENDHT_C_PUBLIC int dht_runner_join(dht_runner* runner);
/* Returns 0 on success, standard error code on failure */
OPENDHT_C_PUBLIC int dht_runner_run(dht_runner* runner, in_port_t port);
/* Returns 0 on success, standard error code on failure */
OPENDHT_C_PUBLIC int dht_runner_run_config(dht_runner* runner, in_port_t port, const dht_runner_config* config);
OPENDHT_C_PUBLIC int dht_runner_run_bind(dht_runner* runner,
                                         const char* ipv4,
                                         const char* ipv6,
                                         in_port_t port,
                                         const dht_runner_config* config,
                                         const dht_runner_context* context);
OPENDHT_C_PUBLIC int dht_runner_connectivity_changed(dht_runner* runner);
OPENDHT_C_PUBLIC int dht_runner_register_type(
    dht_runner* runner, uint16_t id, const char* name, uint64_t expiration_seconds, bool insecure);
OPENDHT_C_PUBLIC dht_publickey* dht_runner_get_publickey(const dht_runner* runner);
OPENDHT_C_PUBLIC void dht_runner_find_certificate(
    dht_runner* runner, const dht_pkid* id, dht_certificate_cb callback, dht_shutdown_cb released_cb, void* user_data);
OPENDHT_C_PUBLIC int dht_runner_register_certificate(dht_runner* runner, const dht_certificate* certificate);
OPENDHT_C_PUBLIC void dht_runner_ping(
    dht_runner* runner, struct sockaddr* addr, socklen_t addr_len, dht_done_cb done_cb, void* cb_user_data);
OPENDHT_C_PUBLIC void dht_runner_bootstrap(dht_runner* runner, const char* host, const char* service);
OPENDHT_C_PUBLIC void dht_runner_get(
    dht_runner* runner, const dht_infohash* hash, dht_get_cb cb, dht_done_cb done_cb, void* cb_user_data);
OPENDHT_C_PUBLIC void dht_runner_get_filtered(dht_runner* runner,
                                              const dht_infohash* hash,
                                              const char* where,
                                              dht_get_cb cb,
                                              dht_done_cb done_cb,
                                              void* user_data);
OPENDHT_C_PUBLIC void dht_runner_query(dht_runner* runner,
                                       const dht_infohash* hash,
                                       const char* query,
                                       dht_query_cb cb,
                                       dht_done_cb done_cb,
                                       void* user_data);
OPENDHT_C_PUBLIC dht_op_token* dht_runner_listen(
    dht_runner* runner, const dht_infohash* hash, dht_value_cb cb, dht_shutdown_cb done_cb, void* cb_user_data);
OPENDHT_C_PUBLIC dht_op_token* dht_runner_listen_filtered(dht_runner* runner,
                                                          const dht_infohash* hash,
                                                          const char* where,
                                                          dht_value_cb cb,
                                                          dht_shutdown_cb released_cb,
                                                          void* user_data);
OPENDHT_C_PUBLIC void dht_runner_cancel_listen(dht_runner* runner, const dht_infohash* hash, dht_op_token* token);
OPENDHT_C_PUBLIC void dht_runner_put(dht_runner* runner,
                                     const dht_infohash* hash,
                                     const dht_value* value,
                                     dht_done_cb done_cb,
                                     void* cb_user_data,
                                     bool permanent);
OPENDHT_C_PUBLIC void dht_runner_put_signed(dht_runner* runner,
                                            const dht_infohash* hash,
                                            const dht_value* value,
                                            dht_done_cb done_cb,
                                            void* cb_user_data,
                                            bool permanent);
OPENDHT_C_PUBLIC void dht_runner_put_encrypted(dht_runner* runner,
                                               const dht_infohash* hash,
                                               const dht_pkid* to,
                                               const dht_value* value,
                                               dht_done_cb done_cb,
                                               void* cb_user_data,
                                               bool permanent);
OPENDHT_C_PUBLIC void dht_runner_cancel_put(dht_runner* runner, const dht_infohash* hash, dht_value_id value_id);
OPENDHT_C_PUBLIC void dht_runner_shutdown(dht_runner* runner, dht_shutdown_cb done_cb, void* cb_user_data);
OPENDHT_C_PUBLIC dht_infohash dht_runner_get_node_id(const dht_runner* runner);
OPENDHT_C_PUBLIC dht_infohash dht_runner_get_id(const dht_runner* runner);
OPENDHT_C_PUBLIC bool dht_runner_is_running(const dht_runner* runner);
OPENDHT_C_PUBLIC in_port_t dht_runner_get_bound_port(const dht_runner* runner, sa_family_t af);
/** Returns null-terminated array that must be freed after use as well as each element */
OPENDHT_C_PUBLIC struct sockaddr** dht_runner_get_public_address(const dht_runner* runner);
OPENDHT_C_PUBLIC void dht_sockaddr_array_delete(struct sockaddr** addresses);
OPENDHT_C_PUBLIC int dht_runner_set_push_notification_token(dht_runner* runner, const char* value);
OPENDHT_C_PUBLIC int dht_runner_set_push_notification_topic(dht_runner* runner, const char* value);
OPENDHT_C_PUBLIC int dht_runner_set_push_notification_platform(dht_runner* runner, const char* value);
OPENDHT_C_PUBLIC dht_push_token* dht_runner_push_notification_received(dht_runner* runner,
                                                                       const char* const* keys,
                                                                       const char* const* values,
                                                                       size_t count);
OPENDHT_C_PUBLIC int dht_push_token_poll(dht_push_token* token, int* result);
OPENDHT_C_PUBLIC void dht_push_token_delete(dht_push_token* token);

#ifdef __cplusplus
}
#endif
