#pragma once

#include <asio.hpp>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace dht {
namespace net {

using asio::ip::udp;
using strand = asio::io_context::strand;

struct ReceivedPacket {
    std::vector<uint8_t> data;
    udp::endpoint from;
    //time_point received;
};


class DatagramSocket {
public:
    /** A function that takes a list of new received packets and
     *  optionally returns consumed packets for recycling.
     **/
    //using OnReceive = std::function<PacketList(PacketList&& packets)>;
    using ReceiveCallback = std::function<void(const ReceivedPacket&)>;

    virtual ~DatagramSocket() {};

    virtual asio::error_code sendTo(const uint8_t* data, size_t size, const udp::endpoint& dest) = 0;

    virtual void setOnReceive(const ReceiveCallback& cb) = 0;/* {
        //std::lock_guard<std::mutex> lk(lock);
        //rx_callback = std::move(cb);
    }*/

    virtual bool hasIPv4() const = 0;
    virtual bool hasIPv6() const = 0;

    virtual udp::endpoint getBound(sa_family_t family = AF_UNSPEC) const = 0;
    in_port_t getPort(sa_family_t family = AF_UNSPEC) const {
        //std::lock_guard<std::mutex> lk(lock);
        return getBound(family).port();
    }

    //virtual const udp::endpoint& getBoundRef(sa_family_t family = AF_UNSPEC) const = 0;

    virtual void stop() = 0;
/*protected:

    PacketList getNewPacket() {
        PacketList pkts;
        if (toRecycle_.empty()) {
            pkts.emplace_back();
        } else {
            auto begIt = toRecycle_.begin();
            auto begItNext = std::next(begIt);
            pkts.splice(pkts.end(), toRecycle_, begIt, begItNext);
        }
        return pkts;
    }

    inline void onReceived(PacketList&& packets) {
        std::lock_guard<std::mutex> lk(lock);
        if (rx_callback) {
            auto r = rx_callback(std::move(packets));
            if (not r.empty() and toRecycle_.size() < RX_QUEUE_MAX_SIZE)
                toRecycle_.splice(toRecycle_.end(), std::move(r));
        }
    }
protected:
    mutable std::mutex lock;*/
private:
    //ReceiveCallback rx_callback;
    //PacketList toRecycle_;
};


class UdpSocket : public DatagramSocket {
public:
    UdpSocket(std::shared_ptr<strand> strand, const udp::endpoint& ipv4_endpoint, const udp::endpoint& ipv6_endpoint);

    void setOnReceive(const ReceiveCallback& callback);
    void start_receive();

    void stop();

    void sendToAsync(std::vector<uint8_t> data, const udp::endpoint& to);
    asio::error_code sendTo(const uint8_t* buf, size_t len, const udp::endpoint& to);

    bool hasIPv4() const;
    bool hasIPv6() const;

    udp::endpoint getBound(sa_family_t af) const;
private:
    class SocketHandler;
    //std::shared_ptr<strand> strand_;
    std::shared_ptr<SocketHandler> ipv4_handler_;
    std::shared_ptr<SocketHandler> ipv6_handler_;
};

}  // namespace net
}  // namespace dht