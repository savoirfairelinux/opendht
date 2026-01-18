// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
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

    using X509Ptr = std::unique_ptr<X509, void (*)(X509*)>;
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
} // namespace http
} // namespace dht
