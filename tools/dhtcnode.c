/*
 *  Copyright (C) 2014-2025 Savoir-faire Linux Inc.
 *  Author : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <opendht_c.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <time.h>

#ifdef _MSC_VER
#include "wingetopt.h"
#else
#include <getopt.h>
#endif
#include <readline/readline.h>
#include <readline/history.h>
#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

struct op_context {
    dht_runner* runner;
    atomic_bool stop;
};
struct listen_context {
    dht_runner* runner;
    dht_op_token* token;
    size_t count;
};
struct put_context {
    dht_runner* runner;
    dht_value* value;
};

bool dht_value_callback(const dht_value* value, bool expired, void* user_data)
{
    struct listen_context* ctx = (struct listen_context*) user_data;
    if (expired)
        ctx->count--;
    else
        ctx->count++;
    dht_data_view data = dht_value_get_data(value);
    printf("Listen: %s value: %.*s (total %zu).\n", expired ? "expired" : "new", (int)data.size, data.data, ctx->count);
    return true;
}

bool dht_get_callback(const dht_value* value, void* user_data)
{
    dht_runner* runner = (dht_runner*)user_data;
    dht_data_view data = dht_value_get_data(value);
    printf("Get callback: %.*s.\n", (int)data.size, data.data);
    return true;
}

void dht_get_done_callback(bool ok, void* user_data)
{
    dht_runner* runner = (dht_runner*)user_data;
    printf("Get completed: %s\n", ok ? "success !" : "failure :-(");
}

void dht_put_done_callback(bool ok, void* user_data)
{
    struct put_context* ctx = (struct put_context*)user_data;
    printf("Put completed (id: %" PRIx64 "): %s\n", dht_value_get_id(ctx->value), ok ? "success !" : "failure :-(");
    dht_value_unref(ctx->value);
    free(ctx);
}

void dht_shutdown_callback(void* user_data)
{
    printf("Stopped.\n");
    struct op_context* ctx = (struct op_context*)user_data;
    atomic_store(&ctx->stop, true);
}

void listen_context_free(void* user_data)
{
    printf("listen_context_free.\n");
    struct listen_context* ctx = (struct listen_context*)user_data;
    dht_op_token_delete(ctx->token);
    free(ctx);
}

char* print_addr(const struct sockaddr* addr) {
    char* s = NULL;
    switch(addr->sa_family) {
    case AF_INET: {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        s = malloc(INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        s = malloc(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
        break;
    }
    default:
        break;
    }
    return s;
}

struct dht_params {
    bool help;
    bool version;
    bool generate_identity;
    bool service;
    bool peer_discovery;
    bool log;
    const char* bootstrap;
    unsigned network;
    in_port_t port;
};

static const struct option long_options[] = {
    {"help",                no_argument      , NULL, 'h'},
    {"port",                required_argument, NULL, 'p'},
    {"net",                 required_argument, NULL, 'n'},
    {"bootstrap",           required_argument, NULL, 'b'},
    {"identity",            no_argument      , NULL, 'i'},
    {"verbose",             no_argument      , NULL, 'v'},
    {"service",             no_argument      , NULL, 's'},
    {"peer-discovery",      no_argument      , NULL, 'D'},
    {"no-rate-limit",       no_argument      , NULL, 'U'},
    {"persist",             required_argument, NULL, 'f'},
    {"logfile",             required_argument, NULL, 'l'},
    {"syslog",              no_argument      , NULL, 'L'},
    {"version",             no_argument      , NULL, 'V'},
    {NULL,                  0                , NULL,  0}
};

struct dht_params
parse_args(int argc, char **argv) {
    struct dht_params params;
    memset(&params, 0, sizeof params);
    int opt;
    while ((opt = getopt_long(argc, argv, "hisvDp:n:b:f:l:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'p': {
                int port_arg = atoi(optarg);
                if (port_arg >= 0 && port_arg < 0x10000)
                    params.port = port_arg;
            }
            break;
        case 'D':
            params.peer_discovery = true;
            break;
        case 'n':
            params.network = strtoul(optarg, NULL, 0);
            break;
        case 'b':
            params.bootstrap = (optarg[0] == '=') ? optarg+1 : optarg;
            break;
        case 'h':
            params.help = true;
            break;
        case 'v':
            params.log = true;
            break;
        case 'i':
            params.generate_identity = true;
            break;
        case 's':
            params.service = true;
            break;
        case 'V':
            params.version = true;
            break;
        default:
            break;
        }
    }
    return params;
}

dht_infohash parse_key(const char* key_str) {
    dht_infohash key;
    dht_infohash_from_hex_null(&key, key_str);
    if (dht_infohash_is_zero(&key)) {
        dht_infohash_get_from_string(&key, key_str);
        printf("Using h(%s) = %s\n", key_str, dht_infohash_print(&key));
    }
    return key;
}

int main(int argc, char **argv)
{
    struct dht_params params = parse_args(argc, argv);

    if (params.version) {
        printf("OpenDHT version %s\n", dht_version());
        return EXIT_SUCCESS;
    }

    dht_runner* runner = dht_runner_new();
    dht_runner_config dht_config;
    dht_runner_config_default(&dht_config);
    dht_config.peer_discovery = params.peer_discovery; // Look for other peers on the network
    dht_config.peer_publish = params.peer_discovery; // Publish our own peer info
    dht_config.dht_config.node_config.network = params.network;
    dht_config.log = params.log;
    dht_runner_run_config(runner, params.port, &dht_config);

    if (params.bootstrap) {
        printf("Bootstrap using %s\n", params.bootstrap);
        dht_runner_bootstrap(runner, params.bootstrap, NULL);
    }

    char cmd[64];
    char arg[64];
    char value[256];
    dht_infohash key;
    while (true) {
        const char* line_read = readline("> ");
        if (!line_read)
            break;
        if (!*line_read)
            continue;
        add_history(line_read);

        memset(cmd, 0, sizeof cmd);
        memset(arg, 0, sizeof arg);
        memset(value, 0, sizeof value);
        sscanf(line_read, "%63s %63s %255s", cmd, arg, value);

        if (!strcmp(cmd, "la")) {
            struct sockaddr** addrs = dht_runner_get_public_address(runner);
            if (addrs) {
                for (struct sockaddr** addrIt = addrs; *addrIt; addrIt++) {
                    struct sockaddr* addr = *addrIt;
                    char* addr_str = print_addr(addr);
                    free(addr);
                    printf("Found public address: %s\n", addr_str);
                    free(addr_str);
                }
                free(addrs);
            }
        }
        else if (!strcmp(cmd, "ll")) {
            key = dht_runner_get_node_id(runner);
            printf("DHT node %s running on port %u\n", dht_infohash_print(&key), dht_runner_get_bound_port(runner, AF_INET));
        }
        else if (!strcmp(cmd, "g")) {
            key = parse_key(arg);
            dht_runner_get(runner, &key, dht_get_callback, dht_get_done_callback, runner);
        }
        else if (!strcmp(cmd, "l")) {
            key = parse_key(arg);
            struct listen_context* ctx = malloc(sizeof(struct listen_context));
            ctx->runner = runner;
            ctx->count = 0;
            ctx->token = dht_runner_listen(runner, &key, dht_value_callback, listen_context_free, ctx);
        }
        else if (!strcmp(cmd, "p")) {
            key = parse_key(arg);
            dht_value* val = dht_value_new_from_string(value);
            struct put_context* ctx = malloc(sizeof(struct put_context));
            ctx->runner = runner;
            ctx->value = val;
            dht_runner_put(runner, &key, val, dht_put_done_callback, ctx, true);
        }
        else {
            printf("Unknown command: %s\n", cmd);
        }
    }

    // Graceful shutdown
    printf("Stopping…\n");
    struct op_context ctx;
    ctx.runner = runner;
    atomic_init(&ctx.stop, false);
    dht_runner_shutdown(runner, dht_shutdown_callback, &ctx);

    // Wait until shutdown callback is called
    while (!atomic_load(&ctx.stop)) {
#ifdef _WIN32
        Sleep(10);              // 10ms
#else
        struct timespec ts = {0, 10000000}; // 10ms
        nanosleep(&ts, NULL);
#endif
    }
    dht_runner_delete(runner);
    return EXIT_SUCCESS;
}
