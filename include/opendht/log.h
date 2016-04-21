/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.
 */

#pragma once

#include "dhtrunner.h"

#include <iostream>
#include <fstream>

namespace dht {
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
void
printLog(std::ostream& s, char const* m, va_list args) {
    static constexpr int BUF_SZ = 8192;
    char buffer[BUF_SZ];
    int ret = vsnprintf(buffer, sizeof(buffer), m, args);
    if (ret < 0)
        return;
    s.write(buffer, std::min(ret, BUF_SZ));
    if (ret >= BUF_SZ)
        s << "[[TRUNCATED]]";
    s.put('\n');
}

void
enableLogging(dht::DhtRunner& dht)
{
    dht.setLoggers(
        [](char const* m, va_list args){ std::cerr << red; printLog(std::cerr, m, args); std::cerr << def; },
        [](char const* m, va_list args){ std::cout << yellow; printLog(std::cout, m, args); std::cout << def; },
        [](char const* m, va_list args){ printLog(std::cout, m, args); }
    );
}

void
enableFileLogging(dht::DhtRunner& dht, const std::string& path)
{
    auto logfile = std::make_shared<std::fstream>();
    logfile->open(path, std::ios::out);

    dht.setLoggers(
        [=](char const* m, va_list args){ printLog(*logfile, m, args); },
        [=](char const* m, va_list args){ printLog(*logfile, m, args); },
        [=](char const* m, va_list args){ printLog(*logfile, m, args); }
    );
}

void
disableLogging(dht::DhtRunner& dht)
{
    dht.setLoggers(dht::NOLOG, dht::NOLOG, dht::NOLOG);
}

} /* log */
} /* dht  */

