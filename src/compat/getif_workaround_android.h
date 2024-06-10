//Code from getifaddrs.3 man
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <asio.hpp>
#include <stdexcept>
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

} /* namespace workaround */
} /* namespace dht */
