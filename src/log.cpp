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

#include "log.h"
#include "dhtrunner.h"

#ifndef _WIN32
#include <syslog.h>
#endif

#include <fstream>
#include <chrono>

namespace dht {
namespace log {

/**
 * Print va_list to std::ostream (used for logging).
 */
void
printLog(std::ostream& s, char const *m, va_list args) {
    // print log to buffer
    std::array<char, 8192> buffer;
    int ret = vsnprintf(buffer.data(), buffer.size(), m, args);
    if (ret < 0)
        return;

    // write timestamp
    using namespace std::chrono;
    using log_precision = microseconds;
    constexpr auto den = log_precision::period::den;
    auto num = duration_cast<log_precision>(steady_clock::now().time_since_epoch()).count();
    s << "[" << std::setfill('0') << std::setw(6) << num / den << "."
             << std::setfill('0') << std::setw(6) << num % den << "]" << " ";

    // write log
    s.write(buffer.data(), std::min((size_t) ret, buffer.size()));
    if ((size_t) ret >= buffer.size())
        s << "[[TRUNCATED]]";
    s << std::endl;
}

std::shared_ptr<Logger>
getStdLogger() {
    return std::make_shared<Logger>(
        [](char const *m, va_list args) {
            std::cerr << red;
            printLog(std::cerr, m, args);
            std::cerr << def;
        },
        [](char const *m, va_list args) {
            std::cout << yellow;
            printLog(std::cout, m, args);
            std::cout << def;
        },
        [](char const *m, va_list args) { printLog(std::cout, m, args); }
    );
}

std::shared_ptr<Logger>
getFileLogger(const std::string &path) {
    auto logfile = std::make_shared<std::ofstream>();
    logfile->open(path, std::ios::out);

    return std::make_shared<Logger>(
        [=](char const *m, va_list args) { printLog(*logfile, m, args); },
        [=](char const *m, va_list args) { printLog(*logfile, m, args); },
        [=](char const *m, va_list args) { printLog(*logfile, m, args); }
    );
}

std::shared_ptr<Logger>
getSyslogLogger(const char* name) {
#ifndef _WIN32
    struct Syslog {
        Syslog(const char* n) {
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
        [logfile](char const *m, va_list args) { vsyslog(LOG_ERR, m, args); },
        [logfile](char const *m, va_list args) { vsyslog(LOG_WARNING, m, args); },
        [logfile](char const *m, va_list args) { vsyslog(LOG_INFO, m, args); }
    );
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
