/*
 *  Copyright (C) 2014-2022 Savoir-faire Linux Inc.
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

#include "log.h"
#include "dhtrunner.h"

#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fmt/printf.h>

#ifndef _WIN32
#include <syslog.h>
#endif

#include <fstream>
#include <chrono>

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
printfLog(std::ostream& s, fmt::string_view format, fmt::printf_args args) {
    using namespace std::chrono;
    using log_precision = microseconds;
    auto num = duration_cast<log_precision>(steady_clock::now().time_since_epoch()).count();
    constexpr auto den = log_precision::period::den;
    fmt::print(s, "[{:06d}.{:06d}] ", num / den, num % den);
    s << fmt::vsprintf(format, args);
    s << std::endl;
}
void
printLog(std::ostream& s, fmt::string_view format, fmt::format_args args) {
    using namespace std::chrono;
    using log_precision = microseconds;
    auto num = duration_cast<log_precision>(steady_clock::now().time_since_epoch()).count();
    constexpr auto den = log_precision::period::den;
    fmt::print(s, "[{:06d}.{:06d}] ", num / den, num % den);
    fmt::vprint(s, format, args);
    s << std::endl;
}

std::shared_ptr<Logger>
getStdLogger() {
    return std::make_shared<Logger>(
        [](LogLevel level, fmt::string_view format, fmt::format_args args) {
            if (level == LogLevel::error)
                std::cerr << red;
            else if (level == LogLevel::warning)
                std::cerr << yellow;
            printLog(std::cerr, format, args);
            std::cerr << def;
        },
        [](LogLevel level, fmt::string_view format, fmt::printf_args args) {
            if (level == LogLevel::error)
                std::cerr << red;
            else if (level == LogLevel::warning)
                std::cerr << yellow;
            printfLog(std::cerr, format, args);
            std::cerr << def;
        }
    );
}

std::shared_ptr<Logger>
getFileLogger(const std::string &path) {
    auto logfile = std::make_shared<std::ofstream>();
    logfile->open(path, std::ios::out);
    return std::make_shared<Logger>(
        [logfile](LogLevel level, fmt::string_view format, fmt::format_args args) {
            printLog(*logfile, format, args);
        },
        [logfile](LogLevel level, fmt::string_view format, fmt::printf_args args) {
            printfLog(*logfile, format, args);
        }
    );
}

constexpr
int syslogLevel(LogLevel level) {
    switch (level) {
    case LogLevel::error:
        return LOG_ERR;
    case LogLevel::warning:
        return LOG_WARNING;
    case LogLevel::debug:
        return LOG_INFO;
    }
    return LOG_ERR;
}

std::shared_ptr<Logger>
getSyslogLogger(const char* name) {
#ifndef _WIN32
    struct Syslog {
        explicit Syslog(const char* n) {
            openlog(n, LOG_NDELAY, LOG_USER);
        }
        ~Syslog() {
            closelog();
        }
    };
    // syslog is global. Existing instance must be reused.
    static std::weak_ptr<Syslog> opened_logfile;
    auto logfile = opened_logfile.lock();
    if (not logfile) {
        logfile = std::make_shared<Syslog>(name);
        opened_logfile = logfile;
    }
    return std::make_shared<Logger>(
        [logfile](LogLevel level, fmt::string_view format, fmt::format_args args) {
            syslog(syslogLevel(level), "%s", fmt::vformat(format, args).c_str());
        },
        [logfile](LogLevel level, fmt::string_view format, fmt::printf_args args) {
            auto fmt = fmt::vsprintf(format, args);
            syslog(syslogLevel(level), "%s", fmt.data());
        });
#else
    return std::make_shared<Logger>();
#endif
}

void
enableLogging(dht::DhtRunner &dht) {
    dht.setLogger(getStdLogger());
}

void
enableFileLogging(dht::DhtRunner &dht, const std::string &path) {
    dht.setLogger(getFileLogger(path));
}

OPENDHT_PUBLIC void
enableSyslog(dht::DhtRunner &dht, const char* name) {
    dht.setLogger(getSyslogLogger(name));
}

void
disableLogging(dht::DhtRunner &dht) {
    dht.setLogger();
}

}
}
