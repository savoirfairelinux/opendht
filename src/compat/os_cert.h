/*
 *  Copyright (c) 2014-2026 Savoir-faire Linux Inc.
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

#pragma once

#include "logger.h"

#include <memory>

#include <openssl/x509.h>

namespace dht {
namespace http {

// A singleton class used to cache the decoded certificates
// loaded from local cert stores that need to be added to the
// ssl context prior to each request.
class PEMCache
{
    PEMCache(const std::shared_ptr<Logger>& l);

    using X509Ptr = std::unique_ptr<X509, void(*)(X509*)>;
    std::vector<X509Ptr> pems_;
    std::shared_ptr<Logger> logger;

public:
    static PEMCache& instance(const std::shared_ptr<Logger>& l)
    {
        static PEMCache instance_(l);
        return instance_;
    }

    void fillX509Store(SSL_CTX* ctx);
};
}
} // namespace dht
