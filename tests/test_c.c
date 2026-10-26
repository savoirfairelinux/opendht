#ifdef NDEBUG
#undef NDEBUG
#endif

#include "opendht_c.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
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
    dht_value_unref(copy);
    puts("C binding regressions passed");
    return 0;
}