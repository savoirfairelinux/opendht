#include <c/opendht_c.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct op_context {
    dht_runner* runner;
    int d;
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

void dht_done_callback(bool ok, void* user_data)
{
    dht_runner* runner = (dht_runner*)user_data;
    printf("Done callback. %s\n", ok ? "Success !" : "Failure :-(");
}

void op_context_free(void* user_data)
{
    struct op_context* ctx = (struct op_context*)user_data;
    printf("op_context_free %d.\n", ctx->d);
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

int main()
{
    dht_identity id = dht_identity_generate("testNode", NULL);
    dht_infohash cert_id = dht_certificate_get_id(id.certificate);
    printf("Cert ID: %s\n", dht_infohash_print(&cert_id));

    dht_publickey* pk = dht_certificate_get_publickey(id.certificate);
    dht_infohash pk_id = dht_publickey_get_id(pk);
    printf("PK ID: %s\n", dht_infohash_print(&pk_id));
    dht_publickey_delete(pk);

    pk = dht_privatekey_get_publickey(id.privatekey);
    pk_id = dht_publickey_get_id(pk);
    printf("Key ID: %s\n", dht_infohash_print(&pk_id));
    dht_publickey_delete(pk);

    dht_identity_delete(&id);

    dht_runner* runner = dht_runner_new();
    dht_runner_run(runner, 4040);

    dht_infohash h;
    dht_infohash_random(&h);

    printf("random hash: %s\n", dht_infohash_print(&h));

    // Put data
    const char* data_str = "yo, this is some data";
    dht_value* val = dht_value_new(data_str, strlen(data_str));
    dht_runner_put(runner, &h, val, dht_done_callback, runner, false);
    dht_value_unref(val);

    // Get data
    dht_runner_get(runner, &h, dht_get_callback, dht_done_callback, runner);

    // Listen for data
    struct op_context* ctx = malloc(sizeof(struct op_context));
    ctx->runner = runner;
    ctx->d = 42;
    dht_op_token* token = dht_runner_listen(runner, &h, dht_value_callback, op_context_free, ctx);

    sleep(1);

    dht_runner_bootstrap(runner, "bootstrap.jami.net", NULL);

    sleep(2);

    struct sockaddr** addrs = dht_runner_get_public_address(runner);
    for (struct sockaddr** addrIt = addrs; *addrIt; addrIt++) {
        struct sockaddr* addr = *addrIt;
        char* addr_str = print_addr(addr);
        free(addr);
        printf("Found public address: %s\n", addr_str);
        free(addr_str);
    }
    free(addrs);

    dht_runner_cancel_listen(runner, &h, token);
    dht_op_token_delete(token);

    dht_runner_delete(runner);
    return 0;
}
