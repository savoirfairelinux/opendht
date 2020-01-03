/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *
 *  Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include "def.h"
#include "log_enable.h"

#include <iostream>
#include <memory>

namespace dht {

class DhtRunner;

/**
 * Logging-related functions
 */
namespace log {

/**
 * Terminal colors for logging
 */
namespace Color {
    enum Code {
        FG_RED      = 31,
        FG_GREEN    = 32,
        FG_YELLOW   = 33,
        FG_BLUE     = 34,
        FG_DEFAULT  = 39,
        BG_RED      = 41,
        BG_GREEN    = 42,
        BG_BLUE     = 44,
        BG_DEFAULT  = 49
    };
    class Modifier {
        const Code code;
    public:
        constexpr Modifier(Code pCode) : code(pCode) {}
        friend std::ostream&
        operator<<(std::ostream& os, const Modifier& mod) {
            return os << "\033[" << mod.code << 'm';
        }
    };
}

constexpr const Color::Modifier def(Color::FG_DEFAULT);
constexpr const Color::Modifier red(Color::FG_RED);
constexpr const Color::Modifier yellow(Color::FG_YELLOW);

/**
 * Print va_list to std::ostream (used for logging).
 */
OPENDHT_PUBLIC void
printLog(std::ostream &s, char const *m, va_list args);

OPENDHT_PUBLIC
std::shared_ptr<Logger> getStdLogger();

OPENDHT_PUBLIC
std::shared_ptr<Logger> getFileLogger(const std::string &path);

OPENDHT_PUBLIC
std::shared_ptr<Logger> getSyslogLogger(const char* name);

OPENDHT_PUBLIC void
enableLogging(dht::DhtRunner &dht);

OPENDHT_PUBLIC void
enableFileLogging(dht::DhtRunner &dht, const std::string &path);

OPENDHT_PUBLIC void
disableLogging(dht::DhtRunner &dht);

OPENDHT_PUBLIC void
enableSyslog(dht::DhtRunner &dht, const char* name);

} /* log */
} /* dht  */
