#ifdef NDEBUG
#undef NDEBUG
#endif

#include "opendht_c.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef _MSC_VER
#include <gnutls/gnutls.h>
#endif

static void
done_cb(bool ok, void* user_data)
{
    int* completed = user_data;
    *completed += ok ? 1 : 10;
}

static bool
get_cb(const dht_value* value, void* user_data)
{
    (void) value;
    (void) user_data;
    return true;
}

static bool
listen_cb(const dht_value* value, bool expired, void* user_data)
{
    (void) expired;
    (void) user_data;
    assert(dht_value_get_id(value) == 42);
    return true;
}

static void
released_cb(void* user_data)
{
    ++*(int*) user_data;
}

int
main(void)
{
#ifdef _MSC_VER
    int crypto_error = gnutls_global_init();
    if (crypto_error != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "Failed to initialize GnuTLS: %s\n", gnutls_strerror(crypto_error));
        return 1;
    }
#endif
    const uint8_t invalid[] = {1, 2, 3};
    assert(dht_publickey_import(invalid, sizeof(invalid)) == NULL);
    assert(dht_privatekey_import(invalid, sizeof(invalid), "") == NULL);
    assert(dht_certificate_import(invalid, sizeof(invalid)) == NULL);
    assert(dht_privatekey_generate(1) == NULL);

    dht_infohash hash;
    dht_infohash_get_from_string(&hash, "binding regression");
    assert(!dht_infohash_is_zero(&hash));
    dht_infohash restored;
    dht_infohash_from_hex_null(&restored, dht_infohash_print(&hash));
    assert(memcmp(&hash, &restored, sizeof(hash)) == 0);

    struct {
        uint32_t alignment;
        uint8_t prefix;
        dht_infohash hash;
    } unaligned = {0};
    dht_infohash_get_from_string(&unaligned.hash, "abc");
    assert(!dht_infohash_is_zero(&unaligned.hash));
    assert(strcmp(dht_infohash_print(&unaligned.hash), "a9993e364706816aba3e25717850c26c9cd0d89d") == 0);
    dht_infohash_from_hex_null(&unaligned.hash, "a9993e364706816aba3e25717850c26c9cd0d89d");
    dht_infohash_from_hex(&restored, dht_infohash_print(&unaligned.hash));
    assert(memcmp(&unaligned.hash, &restored, sizeof(restored)) == 0);
    dht_infohash_zero(&unaligned.hash);
    assert(dht_infohash_is_zero(&unaligned.hash));
    dht_infohash_random(&unaligned.hash);
    assert(!dht_infohash_is_zero(&unaligned.hash));

    dht_value* value = dht_value_with_id_new(invalid, sizeof(invalid), 42);
    assert(value != NULL);
    assert(dht_value_get_id(value) == 42);
    dht_value_set_user_type(value, "application/octet-stream");
    assert(strcmp(dht_value_get_user_type(value), "application/octet-stream") == 0);
    dht_value* copy = dht_value_ref(value);
    dht_value_unref(value);
    dht_data_view data = dht_value_get_data(copy);
    assert(data.size == sizeof(invalid));
    assert(memcmp(data.data, invalid, data.size) == 0);
    dht_value_set_type(copy, 17);
    dht_value_set_seq(copy, 23);
    dht_value_set_priority(copy, 1);
    dht_value_set_push_type(copy, "audioCall");
    assert(dht_value_get_type(copy) == 17);
    assert(dht_value_get_seq(copy) == 23);
    assert(dht_value_get_priority(copy) == 1);
    assert(strcmp(dht_value_get_push_type(copy), "audioCall") == 0);
    dht_value_unref(copy);

    dht_privatekey* private_key = dht_privatekey_generate(2048);
    assert(private_key != NULL);
    dht_publickey* public_key = dht_privatekey_get_publickey(private_key);
    dht_blob* signature = dht_privatekey_sign(private_key, invalid, sizeof(invalid));
    assert(signature != NULL);
    dht_data_view signature_data = dht_blob_get_data(signature);
    assert(dht_publickey_check_signature(public_key,
                                         (const char*) invalid,
                                         sizeof(invalid),
                                         (const char*) signature_data.data,
                                         signature_data.size));
    dht_blob_delete(signature);
    dht_blob* packed = dht_privatekey_export_blob(private_key, "binding-password");
    assert(packed != NULL);
    dht_data_view packed_data = dht_blob_get_data(packed);
    dht_privatekey* imported = dht_privatekey_import(packed_data.data, packed_data.size, "binding-password");
    assert(imported != NULL);
    dht_privatekey_delete(imported);
    dht_blob_delete(packed);
    dht_privatekey_delete(private_key);
    dht_publickey_delete(public_key);

    dht_identity identity = dht_identity_generate("binding regression", NULL);
    assert(identity.privatekey && identity.certificate);
    packed = dht_certificate_export(identity.certificate);
    assert(packed != NULL);
    packed_data = dht_blob_get_data(packed);
    dht_certificate* certificate = dht_certificate_import(packed_data.data, packed_data.size);
    assert(certificate != NULL);
    dht_certificate_delete(certificate);
    dht_blob_delete(packed);
    dht_identity_delete(&identity);

    dht_runner_config config;
    dht_runner_config_default(&config);
    config.threaded = false;
    dht_runner* runner = dht_runner_new();
    assert(dht_runner_run_config(runner, 0, &config) == 0);
    assert(dht_runner_get_bound_port(runner, AF_INET) != 0);
    int released = 0;
    dht_op_token* token = dht_runner_listen(runner, &hash, listen_cb, released_cb, &released);
    int completed = 0;
    value = dht_value_with_id_new(invalid, sizeof(invalid), 42);
    dht_runner_put(runner, &hash, value, done_cb, &completed, false);
    dht_value_unref(value);
    assert(completed == 0);
    assert(dht_runner_loop(runner) == 0);
    dht_runner_get(runner, &hash, get_cb, done_cb, &completed);
    assert(dht_runner_join(runner) == 0);
    assert(!dht_runner_is_running(runner));
    assert(released == 1);
    assert(completed >= 10);
    dht_op_token_delete(token);
    assert(dht_runner_run(runner, 0) == 0);
    assert(dht_runner_join(runner) == 0);
    dht_runner_delete(runner);
#ifdef _MSC_VER
    gnutls_global_deinit();
#endif
    puts("C binding regressions passed");
    return 0;
}