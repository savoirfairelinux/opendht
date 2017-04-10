#include "c/opendht_c.h"
#include <stdio.h>

bool dht_get_callback(const dht_value* value, void* user_data)
{
    dht_runner* runner = (dht_runner*)user_data;
    printf("Get callback.");
}

bool dht_done_callback(bool ok, void* user_data)
{
    dht_runner* runner = (dht_runner*)user_data;
    printf("Done callback. %s", ok ? "Success !" : "Failure :-(");
}

int main()
{
    dht_runner* runner = dht_runner_new();

    dht_infohash h;
    dht_infohash_random(&h);

    printf("random hash: %s\n", dht_infohash_print(&h));

    dht_runner_get(runner, &h, dht_get_callback, dht_done_callback, runner);

    dht_runner_delete(runner);

    return 0;
}
