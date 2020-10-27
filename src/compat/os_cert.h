/*
 *  Copyright (C) 2020 Savoir-faire Linux Inc.
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

#include "log_enable.h"

#include <memory>

#include <openssl/x509.h>

#ifdef _WIN32
#define V_ASN1_UTCTIME         23
#define V_ASN1_GENERALIZEDTIME 24
#define timegm                 _mkgmtime
int ASN1_time_parse(const char* bytes, size_t len, struct tm* tm, int mode);
#endif /*_WIN32*/

namespace dht {
namespace http {
void addSystemCaCertificates(SSL_CTX* ctx, const std::shared_ptr<Logger>& logger);
}
} // namespace dht
