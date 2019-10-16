#include <c/opendht_c.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

bool dht_value_callback(const dht_value* value, bool expired, void* user_data)
{
    dht_runner* runner = (dht_runner*)user_data;
    dht_data_view data = dht_value_get_data(value);
    printf("Value callback %s: %.*s.\n", expired ? "expired" : "new", (int)data.size, data.data);
}

bool dht_get_callback(const dht_value* value, void* user_data)
{
    dht_runner* runner = (dht_runner*)user_data;
    dht_data_view data = dht_value_get_data(value);
    printf("Get callback: %.*s.\n", (int)data.size, data.data);
}

bool dht_done_callback(bool ok, void* user_data)
{
    dht_runner* runner = (dht_runner*)user_data;
    printf("Done callback. %s\n", ok ? "Success !" : "Failure :-(");
}

int main()
{
    dht_runner* runner = dht_runner_new();
    dht_runner_run(runner, 4040);

    dht_infohash h;
    dht_infohash_random(&h);

    printf("random hash: %s\n", dht_infohash_print(&h));

    // Put data
    const char* data_str = "yo, this is some data";
    dht_value* val = dht_value_new(data_str, strlen(data_str));
    dht_runner_put(runner, &h, val, dht_done_callback, runner);
    dht_value_unref(val);

    // Get data
    dht_runner_get(runner, &h, dht_get_callback, dht_done_callback, runner);

    // Listen for data
    dht_op_token* token = dht_runner_listen(runner, &h, dht_value_callback, runner);

    sleep(1);

    dht_runner_cancel_listen(runner, &h, token);
    dht_op_token_delete(token);

    dht_runner_delete(runner);
    return 0;
}
