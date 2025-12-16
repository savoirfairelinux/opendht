//Code from getifaddrs.3 man
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <asio.hpp>
#include <stdexcept>
#include <set>
#include <array>
namespace dht{
namespace workaround{

asio::ip::address_v4
get_interface(){
    struct ifaddrs *ifaddr;
    if(getifaddrs(&ifaddr) == -1){
        throw std::runtime_error("Can't getifaddrs");
    }
    for (struct ifaddrs *if1 = ifaddr; if1 != NULL; if1 = if1->ifa_next){
        if (if1->ifa_addr == NULL)
            continue;
        if (if1->ifa_addr->sa_family != AF_INET)
            continue;
        if((if1->ifa_flags & IFF_MULTICAST) == IFF_MULTICAST){
            auto sa_data = reinterpret_cast<uint8_t*>(if1->ifa_addr->sa_data);
            uint32_t value = sa_data[2] << 24
                | sa_data[3] << 16
                | sa_data[4] << 8
                | sa_data[5];
            freeifaddrs(ifaddr);
            return asio::ip::address_v4(value);
        }
    }
    freeifaddrs(ifaddr);
    throw std::runtime_error("Can't find a interface which supports multicast");
}

std::set<unsigned int> get_if_index_v6(){
    std::set<unsigned int> ifs_set;
    struct ifaddrs *ifaddr;
    if(getifaddrs(&ifaddr) == -1) return ifs_set;
    for (struct ifaddrs *if1 = ifaddr; if1 != NULL; if1 = if1->ifa_next){
        if (if1->ifa_addr == NULL)
            continue;
        if (if1->ifa_addr->sa_family != AF_INET6)
            continue;
        if((if1->ifa_flags & IFF_MULTICAST) == IFF_MULTICAST){
            auto if_index = if_nametoindex(if1->ifa_name);
            ifs_set.insert(if_index);
        }
    }
    freeifaddrs(ifaddr);
    return ifs_set;
}

void try_joingroup_on_all_if_v6(const asio::ip::address_v6 addr, asio::ip::udp::socket &socket){
    auto ifs=get_if_index_v6();

    asio::error_code ec;
    for(auto index : ifs){
        //Ignore the error, most are "address in use". (We may join the second time if connectivityChanged() is called)
        socket.set_option(asio::ip::multicast::join_group(addr, index), ec);
    }
}

void try_sendto_on_all_if_v6(const asio::ip::udp::endpoint addr, asio::const_buffer msg, asio::ip::udp::socket &socket){
    auto ifs=get_if_index_v6();
    if(ifs.empty() ) return;

    auto fd=socket.native_handle();
    struct iovec iov={
        (void*)msg.data(),
        msg.size()
    };
    struct msghdr haha_msg = {};
    haha_msg.msg_name = (void*) addr.data();
    haha_msg.msg_namelen = addr.size();
    haha_msg.msg_iov = &iov;
    haha_msg.msg_iovlen = 1;

    std::array<uint8_t, CMSG_SPACE(sizeof(struct in6_pktinfo))> haha_cmsg = {};
    haha_msg.msg_control = haha_cmsg.data();
    haha_msg.msg_controllen = haha_cmsg.size();

    auto cmsg = reinterpret_cast<struct cmsghdr*>(haha_cmsg.data());
    cmsg->cmsg_level = SOL_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_SPACE(sizeof(struct in6_pktinfo));

    auto pktinfo = reinterpret_cast<struct in6_pktinfo*>(CMSG_DATA(cmsg));

    for(auto index : ifs){
        pktinfo->ipi6_ifindex = index;
        sendmsg(fd, &haha_msg, 0);
    }
}

} /* namespace workaround */
} /* namespace dht */
