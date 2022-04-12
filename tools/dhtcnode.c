/*
 *  Copyright (C) 2014-2022 Savoir-faire Linux Inc.
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

#include <getopt.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdatomic.h>

struct op_context {
    dht_runner* runner;
    atomic_bool stop;
};
struct listen_context {
    dht_runner* runner;
    dht_op_token* token;
};

bool dht_value_callback(const dht_value* value, bool expired, void* user_data)
{
    dht_data_view data = dht_value_get_data(value);
    printf("Value callback %s: %.*s.\n", expired ? "expired" : "new", (int)data.size, data.data);
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
    dht_runner* runner = (dht_runner*)user_data;
    printf("Put completed: %s\n", ok ? "success !" : "failure :-(");
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
    {"help",                    no_argument      , NULL, 'h'},
    {"port",                    required_argument, NULL, 'p'},
    {"net",                     required_argument, NULL, 'n'},
    {"bootstrap",               required_argument, NULL, 'b'},
    {"identity",                no_argument      , NULL, 'i'},
    {"verbose",                 no_argument      , NULL, 'v'},
    {"service",                 no_argument      , NULL, 's'},
    {"peer-discovery",          no_argument      , NULL, 'D'},
    {"no-rate-limit",           no_argument      , NULL, 'U'},
    {"persist",                 required_argument, NULL, 'f'},
    {"logfile",                 required_argument, NULL, 'l'},
    {"syslog",                  no_argument      , NULL, 'L'},
    {NULL,                      0                , NULL,  0}
};

struct dht_params
parse_args(int argc, char **argv) {
    struct dht_params params;
    bzero(&params, sizeof params);
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
        default:
            break;
        }
    }
    return params;
}

int main(int argc, char **argv)
{
    struct dht_params params = parse_args(argc, argv);

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
    while (true) {
        const char* line_read = readline("> ");
        if (line_read && *line_read)
            add_history(line_read);
        if (!line_read)
            break;
        if (!strcmp(line_read, "\0"))
            continue;

        bzero(cmd, sizeof cmd);
        bzero(arg, sizeof arg);
        bzero(value, sizeof value);
        sscanf(line_read, "%64s %64s %256s", cmd, arg, value);

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
            continue;
        }

        dht_infohash key;
        dht_infohash_from_hex(&key, arg);
        if (dht_infohash_is_zero(&key)) {
            dht_infohash_get_from_string(&key, arg);
            printf("Using h(%s) = %s\n", arg, dht_infohash_print(&key));
        }
        if (!strcmp(cmd, "g")) {
            dht_runner_get(runner, &key, dht_get_callback, dht_get_done_callback, runner);
        } else if (!strcmp(cmd, "l")) {
            struct listen_context* ctx = malloc(sizeof(struct listen_context));
            ctx->runner = runner;
            ctx->token = dht_runner_listen(runner, &key, dht_value_callback, listen_context_free, ctx);
        } else if (!strcmp(cmd, "p")) {
            dht_value* val = dht_value_new_from_string(value);
            dht_runner_put(runner, &key, val, dht_put_done_callback, runner, true);
            dht_value_unref(val);
        }
    }
    printf("Stopping..\n");

    struct op_context ctx;
    ctx.runner = runner;
    atomic_init(&ctx.stop, false);
    dht_runner_shutdown(runner, dht_shutdown_callback, &ctx);
    while (!atomic_load(&ctx.stop)) {
        usleep(250);
    }
    dht_runner_delete(runner);
    return 0;
}
