/*
 *  Copyright (C) 2014-2023 Savoir-faire Linux Inc.
 *  Author: Andreas Traczyk <andreas.traczyk@savoirfairelinux.com>
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

#if (defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER > 0x20501000L))
#define EMBEDDED_ASN1_TIME_PARSE 0
#else
#define EMBEDDED_ASN1_TIME_PARSE 1
#endif

#if EMBEDDED_ASN1_TIME_PARSE
#define V_ASN1_UTCTIME         23
#define V_ASN1_GENERALIZEDTIME 24

extern "C" {
/*
 * Parse an RFC 5280 format ASN.1 time string.
 *
 * mode must be:
 * 0 if we expect to parse a time as specified in RFC 5280 for an X509 object.
 * V_ASN1_UTCTIME if we wish to parse an RFC5280 format UTC time.
 * V_ASN1_GENERALIZEDTIME if we wish to parse an RFC5280 format Generalized time.
 *
 * Returns:
 * -1 if the string was invalid.
 * V_ASN1_UTCTIME if the string validated as a UTC time string.
 * V_ASN1_GENERALIZEDTIME if the string validated as a Generalized time string.
 *
 * Fills in *tm with the corresponding time if tm is non NULL.
 */
int ASN1_time_parse(const char* bytes, size_t len, struct tm* tm, int mode);
}
#endif

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
