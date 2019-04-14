/*
 *  Copyright (C) 2019 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "network_utils.h"

#ifndef _WIN32
#include "utils.h"
#include "sockaddr.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#define close(x) closesocket(x)
#define write(s, b, f) send(s, b, (int)strlen(b), 0)
#endif
#include <fcntl.h>

#include <string>

namespace dht {
namespace net {

bool
set_nonblocking(int fd, bool nonblocking)
{
#ifdef _WIN32
    unsigned long mode = !!nonblocking;
    int rc = ioctlsocket(fd, FIONBIO, &mode);
    return rc == 0;
#else
    int rc = fcntl(fd, F_GETFL, 0);
    if (rc < 0)
        return false;
    rc = fcntl(fd, F_SETFL, nonblocking ? (rc | O_NONBLOCK) : (rc & ~O_NONBLOCK));
    return rc >= 0;
#endif
}

#ifdef _WIN32
void udpPipe(int fds[2])
{
    int lst = socket(AF_INET, SOCK_DGRAM, 0);
    if (lst < 0)
        throw DhtException(std::string("Can't open socket: ") + strerror(WSAGetLastError()));
    sockaddr_in inaddr;
    sockaddr addr;
    memset(&inaddr, 0, sizeof(inaddr));
    memset(&addr, 0, sizeof(addr));
    inaddr.sin_family = AF_INET;
    inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    inaddr.sin_port = 0;
    int yes = 1;
    setsockopt(lst, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
    int rc = bind(lst, (sockaddr*)&inaddr, sizeof(inaddr));
    if (rc < 0) {
        close(lst);
        throw DhtException("Can't bind socket on " + print_addr((sockaddr*)&inaddr, sizeof(inaddr)) + " " + strerror(rc));
    }
    socklen_t len = sizeof(addr);
    getsockname(lst, &addr, &len);
    fds[0] = lst;
    fds[1] = socket(AF_INET, SOCK_DGRAM, 0);
    connect(fds[1], &addr, len);
}
#endif

}
}
