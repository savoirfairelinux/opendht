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

struct OPENDHT_C_PUBLIC dht_value;
typedef struct dht_value dht_value;

struct OPENDHT_C_PUBLIC dht_infohash { uint8_t d[HASH_LEN]; };
typedef struct dht_infohash dht_infohash;
OPENDHT_C_PUBLIC void dht_infohash_random(dht_infohash* h);
OPENDHT_C_PUBLIC const char* dht_infohash_print(const dht_infohash* h);

typedef bool (*dht_get_cb)(const dht_value* value, void* user_data);
typedef bool (*dht_done_cb)(bool ok, void* user_data);

struct OPENDHT_C_PUBLIC dht_runner;
typedef struct dht_runner dht_runner;
OPENDHT_C_PUBLIC dht_runner* dht_runner_new();
OPENDHT_C_PUBLIC void dht_runner_delete(dht_runner* runner);
OPENDHT_C_PUBLIC void dht_runner_run(dht_runner* runner, in_port_t port);
OPENDHT_C_PUBLIC void dht_runner_ping(dht_runner* runner, struct sockaddr* addr, socklen_t addr_len);
OPENDHT_C_PUBLIC void dht_runner_get(dht_runner* runner, const dht_infohash* hash, dht_get_cb cb, dht_done_cb done_cb, void* cb_user_data);

#ifdef __cplusplus
}
#endif
