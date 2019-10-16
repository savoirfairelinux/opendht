#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "def.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Non-owning data view
struct OPENDHT_C_PUBLIC dht_data_view {
    const uint8_t* data;
    size_t size;
};
typedef struct dht_data_view dht_data_view;

// dht::Value
struct OPENDHT_C_PUBLIC dht_value;
typedef struct dht_value dht_value;
OPENDHT_C_PUBLIC dht_data_view dht_value_get_data(const dht_value* data);
OPENDHT_C_PUBLIC dht_value* dht_value_new(const uint8_t* data, size_t size);
OPENDHT_C_PUBLIC dht_value* dht_value_ref(const dht_value*);
OPENDHT_C_PUBLIC void dht_value_unref(dht_value*);

// dht::Blob
struct OPENDHT_C_PUBLIC dht_blob;
typedef struct dht_blob dht_blob;
OPENDHT_C_PUBLIC dht_data_view dht_blob_get_data(const dht_blob* data);
OPENDHT_C_PUBLIC void dht_blob_delete(dht_blob* data);

// dht::InfoHash
struct OPENDHT_C_PUBLIC dht_infohash { uint8_t d[HASH_LEN]; };
typedef struct dht_infohash dht_infohash;
OPENDHT_C_PUBLIC void dht_infohash_zero(dht_infohash* h);
OPENDHT_C_PUBLIC void dht_infohash_random(dht_infohash* h);
OPENDHT_C_PUBLIC const char* dht_infohash_print(const dht_infohash* h);
OPENDHT_C_PUBLIC bool dht_infohash_is_zero(const dht_infohash* h);

// dht::PkId
struct OPENDHT_C_PUBLIC dht_pkid { uint8_t d[32]; };
typedef struct dht_pkid dht_pkid;
OPENDHT_C_PUBLIC const char* dht_pkid_print(const dht_pkid* h);

// dht::crypto::PublicKey
struct OPENDHT_C_PUBLIC dht_publickey;
typedef struct dht_publickey dht_publickey;
OPENDHT_C_PUBLIC dht_publickey* dht_publickey_new();
OPENDHT_C_PUBLIC void dht_publickey_delete(dht_publickey* pk);
OPENDHT_C_PUBLIC int dht_publickey_unpack(dht_publickey* pk, const uint8_t* dat, size_t dat_size);
OPENDHT_C_PUBLIC int dht_publickey_pack(dht_publickey* pk, char* out, size_t* out_size);
OPENDHT_C_PUBLIC dht_infohash dht_publickey_get_id(const dht_publickey* pk);
OPENDHT_C_PUBLIC dht_pkid dht_publickey_get_long_id(const dht_publickey* pk);
OPENDHT_C_PUBLIC bool dht_publickey_check_signature(const dht_publickey* pk, const char* data, size_t data_size, const char* signature, size_t signature_size);
OPENDHT_C_PUBLIC dht_blob* dht_publickey_encrypt(const dht_publickey* pk, const char* data, size_t data_size);

// dht::crypto::PrivateKey
struct OPENDHT_C_PUBLIC dht_privatekey;
typedef struct dht_privatekey dht_privatekey;
OPENDHT_C_PUBLIC dht_privatekey* dht_privatekey_generate(unsigned key_length_bits);
OPENDHT_C_PUBLIC dht_privatekey* dht_privatekey_import(const uint8_t* dat, size_t dat_size, const char* password);
OPENDHT_C_PUBLIC dht_publickey* dht_privatekey_get_publickey(const dht_privatekey*);

// dht::crypto::Certificate
struct OPENDHT_C_PUBLIC dht_certificate;
typedef struct dht_certificate dht_certificate;

// callbacks
typedef bool (*dht_get_cb)(const dht_value* value, void* user_data);
typedef bool (*dht_value_cb)(const dht_value* value, bool expired, void* user_data);
typedef bool (*dht_done_cb)(bool ok, void* user_data);
typedef bool (*dht_shutdown_cb)(void* user_data);

// dht::DhtRunner
struct OPENDHT_C_PUBLIC dht_op_token;
typedef struct dht_op_token dht_op_token;
OPENDHT_C_PUBLIC void dht_op_token_delete(dht_op_token* token);

struct OPENDHT_C_PUBLIC dht_runner;
typedef struct dht_runner dht_runner;
OPENDHT_C_PUBLIC dht_runner* dht_runner_new();
OPENDHT_C_PUBLIC void dht_runner_delete(dht_runner* runner);
OPENDHT_C_PUBLIC void dht_runner_run(dht_runner* runner, in_port_t port);
OPENDHT_C_PUBLIC void dht_runner_ping(dht_runner* runner, struct sockaddr* addr, socklen_t addr_len);
OPENDHT_C_PUBLIC void dht_runner_bootstrap(dht_runner* runner, const char* host, const char* service);
OPENDHT_C_PUBLIC void dht_runner_get(dht_runner* runner, const dht_infohash* hash, dht_get_cb cb, dht_done_cb done_cb, void* cb_user_data);
OPENDHT_C_PUBLIC dht_op_token* dht_runner_listen(dht_runner* runner, const dht_infohash* hash, dht_value_cb cb, void* cb_user_data);
OPENDHT_C_PUBLIC void dht_runner_cancel_listen(dht_runner* runner, const dht_infohash* hash, dht_op_token* token);
OPENDHT_C_PUBLIC void dht_runner_shutdown(dht_runner* runner, dht_shutdown_cb done_cb, void* cb_user_data);

#ifdef __cplusplus
}
#endif
