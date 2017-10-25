// TODO gpl

#pragma once

#include "def.h"

#include <thread>
#include <memory>

// TODO add ifdef RESTBED
#include <restbed>

namespace dht {

class DhtRunner;

class OPENDHT_PUBLIC DhtProxyServer
{
public:
    DhtProxyServer(DhtRunner* dht);
    virtual ~DhtProxyServer();

    DhtProxyServer(const DhtProxyServer& other) = default;
    DhtProxyServer(DhtProxyServer&& other) = default;
    DhtProxyServer& operator=(const DhtProxyServer& other) = default;
    DhtProxyServer& operator=(DhtProxyServer&& other) = default;

private:
    void getId(const std::shared_ptr<restbed::Session>& session) const;
    void getNodeId(const std::shared_ptr<restbed::Session>& session) const;
    void putSigned(const std::shared_ptr<restbed::Session>& session) const;

    std::thread server_thread {};
    std::unique_ptr<restbed::Service> service_;
    DhtRunner* dht_;
};

}
