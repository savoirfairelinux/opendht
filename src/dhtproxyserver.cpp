// TODO GPL

#include "dhtproxyserver.h"

#include <functional>

#include "dhtrunner.h"

namespace dht {

DhtProxyServer::DhtProxyServer(DhtRunner* dht) : dht_(dht)
{
    // NOTE in c++14, use make_unique
    service_ = std::unique_ptr<restbed::Service>(new restbed::Service());

    auto resource = std::make_shared<restbed::Resource>();
    resource->set_path("/getId");
    resource->set_method_handler("GET",
        [this](const std::shared_ptr<restbed::Session> session)
        {
            this->getId(session);
        }
    );
    service_->publish(resource);
    resource = std::make_shared<restbed::Resource>();
    resource->set_path("/getNodeId");
    resource->set_method_handler("GET",
        [this](const std::shared_ptr<restbed::Session> session)
        {
            this->getNodeId(session);
        }
    );
    service_->publish(resource);

    server_thread = std::thread([this]() {
        auto settings = std::make_shared<restbed::Settings>();
        settings->set_port(1984); // TODO add argument and move this
        settings->set_default_header("Connection", "close");
        service_->start(settings);
    });
}

DhtProxyServer::~DhtProxyServer()
{
    if (server_thread.joinable())
        server_thread.join();
}

void
DhtProxyServer::getId(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();

    int content_length = std::stoi(request->get_header("Content-Length", "0"));

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                auto id = dht_->getId().toString();
                s->close(restbed::OK, id, {{"Content-Length", std::to_string(id.length())}});
            } else {
                s->close(restbed::OK, "", {{"Content-Length", "0"}});
            }
        }
    );
}

void
DhtProxyServer::getNodeId(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();

    int content_length = std::stoi(request->get_header("Content-Length", "0"));

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                auto id = dht_->getNodeId().toString();
                s->close(restbed::OK, id, {{"Content-Length", std::to_string(id.length())}});
            } else {
                s->close(restbed::OK, "", {{"Content-Length", "0"}});
            }
        }
    );
}


}
