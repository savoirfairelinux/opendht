#include "udp_socket.h"

namespace dht {
namespace net {


class UdpSocket::SocketHandler : public std::enable_shared_from_this<UdpSocket::SocketHandler> {
public:
    SocketHandler(const std::shared_ptr<strand>& strand, const udp::endpoint& endpoint)
    : strand_(strand), socket_(strand->context())
    {
        asio::error_code ec;
        socket_.open(endpoint.protocol(), ec);
        if (ec)
            throw std::runtime_error("Failed to open socket: " + ec.message());

        socket_.set_option(asio::socket_base::reuse_address(true), ec);
        if (ec)
            throw std::runtime_error("Failed to set socket option: " + ec.message());

        socket_.bind(endpoint, ec);
        if (ec)
            throw std::runtime_error("Failed to bind socket: " + ec.message());
    }
    void set_receive_callback(const ReceiveCallback& callback) {
        receive_callback_ = callback;
    }

    void start_receive() {
        receive_next();
    }

    void stop() {
        socket_.close();
    }

    void send_to_async(std::vector<uint8_t> data, const udp::endpoint& to) {
        auto ctx = std::make_shared<std::vector<uint8_t>>(std::move(data));
        socket_.async_send_to(asio::buffer(*ctx), to, [ctx](const asio::error_code&, std::size_t) {});
    }

    asio::error_code send_to(const uint8_t* buf, size_t len, const udp::endpoint& to) {
        asio::error_code ec;
        socket_.send_to(asio::buffer(buf, len), to, 0, ec);
        return ec;
    }

    udp::endpoint getBound() const {
        return socket_.local_endpoint();
    }

private:
    void receive_next() {
        socket_.async_receive_from(asio::buffer(receive_buffer_),
                remote_endpoint_,
                asio::bind_executor(*strand_, [self = shared_from_this()](const asio::error_code& error, std::size_t bytes) {
                    self->handle_receive(error, bytes);
                    self->receive_next();
                }));
    }

    void handle_receive(const asio::error_code& error, std::size_t bytes) {
        if (!error) {
            if (receive_callback_) {
                receive_callback_(ReceivedPacket{std::vector<uint8_t>(receive_buffer_.begin(), receive_buffer_.begin() + bytes),
                                      remote_endpoint_/*, std::chrono::high_resolution_clock::now()*/});
            }
        } else {
            // Handle error
        }
    }

    std::shared_ptr<strand> strand_;
    udp::socket socket_;
    udp::endpoint remote_endpoint_;
    std::array<uint8_t, 65536> receive_buffer_;
    ReceiveCallback receive_callback_;
};

UdpSocket::UdpSocket(std::shared_ptr<strand> strand, const udp::endpoint& ipv4_endpoint, const udp::endpoint& ipv6_endpoint)
    //: strand_(strand)
{
    try {
        ipv4_handler_ = std::make_shared<SocketHandler>(strand, ipv4_endpoint);
    } catch (const std::exception&) {

    }

    // Try to use the same port for IPv6 if not specified
    udp::endpoint ipv6_endpoint_stack;
    if (ipv6_endpoint.port() == 0) {
        ipv6_endpoint_stack = ipv6_endpoint;
        ipv6_endpoint_stack.port(ipv4_handler_->getBound().port());
    }
    const auto& ipv6_endpoint_to_use = ipv6_endpoint.port() == 0 ? ipv6_endpoint_stack : ipv6_endpoint;

    try {
        ipv6_handler_ = std::make_shared<SocketHandler>(strand, ipv6_endpoint_to_use);
    } catch (const std::exception&) {
        
    }
    if (!ipv4_handler_ && !ipv6_handler_)
        throw std::runtime_error("Failed to bind sockets");
}

void UdpSocket::setOnReceive(const ReceiveCallback& callback) {
    ipv4_handler_->set_receive_callback(callback);
    ipv6_handler_->set_receive_callback(callback);
    start_receive();
}

void UdpSocket::start_receive() {
    ipv4_handler_->start_receive();
    ipv6_handler_->start_receive();
}

void UdpSocket::stop() {
    ipv4_handler_->stop();
    ipv6_handler_->stop();
}

void UdpSocket::sendToAsync(std::vector<uint8_t> data, const udp::endpoint& to) {
    auto handler = (to.address().is_v4()) ? ipv4_handler_ : ipv6_handler_;
    handler->send_to_async(std::move(data), to);
}

asio::error_code UdpSocket::sendTo(const uint8_t* buf, size_t len, const udp::endpoint& to) {
    auto handler = (to.address().is_v4()) ? ipv4_handler_ : ipv6_handler_;
    return handler->send_to(buf, len, to);
}

bool UdpSocket::hasIPv4() const {
    return ipv4_handler_ != nullptr;
}

bool UdpSocket::hasIPv6() const {
    return ipv6_handler_ != nullptr;
}

udp::endpoint UdpSocket::getBound(sa_family_t af) const {
    if (af == AF_INET && ipv4_handler_) {
        return ipv4_handler_->getBound();
    } else if (af == AF_INET6 && ipv6_handler_) {
        return ipv6_handler_->getBound();
    }
    throw std::runtime_error("Invalid address family");
}

}  // namespace net
}  // namespace dht
