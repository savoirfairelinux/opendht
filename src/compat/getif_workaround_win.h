#include <set>
#include <array>
#include <vector>
#include <winsock2.h>
#include <iphlpapi.h>
#include <asio.hpp>

namespace dht{
namespace workaround{
std::set<unsigned int> get_if_index_v6(){
    const DWORD flags = GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_UNICAST;
    const uint32_t MAX_TRIES = 3;
    ULONG l = 16384;
    ULONG ret = 0;
    uint32_t count=0;
    std::vector<uint8_t> buf{};
    do {
        buf.resize(l);
        ret = GetAdaptersAddresses(AF_INET6, flags, nullptr, (IP_ADAPTER_ADDRESSES*)buf.data(), &l);
        count++;
    } while ((ret == ERROR_BUFFER_OVERFLOW) && (count < MAX_TRIES));

    std::set<unsigned int> ifs_set;
    if(ret == NO_ERROR){
        auto aas = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        for(PIP_ADAPTER_ADDRESSES aa = aas; aa!=nullptr; aa = aa->Next){
            if(((aa->Flags & IP_ADAPTER_NO_MULTICAST) == 0) && (aa->Ipv6IfIndex != 0))
                ifs_set.insert(aa->Ipv6IfIndex);
        }
    }
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
    if(ifs.empty()) return;

    auto fd=socket.native_handle();
    WSABUF iov={
        static_cast<u_long>(msg.size()),
        (char*)msg.data()
    };
    WSAMSG haha_msg = {};
    haha_msg.name = (LPSOCKADDR)addr.data();
    haha_msg.namelen = addr.size();
    haha_msg.lpBuffers = &iov;
    haha_msg.dwBufferCount = 1;

    std::array<uint8_t, WSA_CMSG_SPACE(sizeof(struct in6_pktinfo))> haha_cmsg{};
    haha_msg.Control = WSABUF{
        static_cast<u_long>(haha_cmsg.size()),
        (char*)haha_cmsg.data()
    };

    auto cmsg = reinterpret_cast<WSACMSGHDR*>(haha_cmsg.data());
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = WSA_CMSG_SPACE(sizeof(struct in6_pktinfo));

    auto pktinfo = reinterpret_cast<struct in6_pktinfo*>(WSA_CMSG_DATA(cmsg));
    DWORD l;

    for(auto index : ifs){
        pktinfo->ipi6_ifindex = index;
        WSASendMsg(fd, &haha_msg, 0, &l, nullptr, nullptr);//Does WSASendMsg support nonoverlapped usage on an overlapped socket?
    }
}
} /* namespace workaround */
} /* namespace dht */