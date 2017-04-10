#include "opendht_c.h"
#include "opendht.h"

#ifdef __cplusplus
extern "C" {
#endif

const char* dht_infohash_print(const dht_infohash* h)
{
    return reinterpret_cast<const dht::InfoHash*>(h)->to_c_str();
}

void dht_infohash_random(dht_infohash* h)
{
    *reinterpret_cast<dht::InfoHash*>(h) = dht::InfoHash::getRandom();
}

dht_runner* dht_runner_new() {
    return reinterpret_cast<dht_runner*>(new dht::DhtRunner);
}

void dht_runner_delete(dht_runner* runner) {
    delete reinterpret_cast<dht::DhtRunner*>(runner);
}

void dht_runner_run(dht_runner* r, in_port_t port)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    runner->run(port, {}, true);
}

void dht_runner_ping(dht_runner* r, struct sockaddr* addr, socklen_t addr_len)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    runner->bootstrap(dht::SockAddr(addr, addr_len));
}

void dht_runner_get(dht_runner* r, const dht_infohash* h, dht_get_cb cb, dht_done_cb done_cb, void* cb_user_data)
{
    auto runner = reinterpret_cast<dht::DhtRunner*>(r);
    auto hash = reinterpret_cast<const dht::InfoHash*>(h);
    runner->get(*hash, [cb,cb_user_data](std::shared_ptr<dht::Value> value){
        return cb(reinterpret_cast<dht_value*>(value.get()), cb_user_data);
    }, [done_cb, cb_user_data](bool ok){
        done_cb(ok, cb_user_data);
    });
}

#ifdef __cplusplus
}
#endif
