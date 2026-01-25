// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

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
    FG_RED = 31,
    FG_GREEN = 32,
    FG_YELLOW = 33,
    FG_BLUE = 34,
    FG_DEFAULT = 39,
    BG_RED = 41,
    BG_GREEN = 42,
    BG_BLUE = 44,
    BG_DEFAULT = 49
};
class Modifier
{
    const Code code;

public:
    constexpr Modifier(Code pCode)
        : code(pCode)
    {}
    friend std::ostream& operator<<(std::ostream& os, const Modifier& mod) { return os << "\033[" << mod.code << 'm'; }
};
} // namespace Color

constexpr const Color::Modifier def(Color::FG_DEFAULT);
constexpr const Color::Modifier red(Color::FG_RED);
constexpr const Color::Modifier yellow(Color::FG_YELLOW);

using namespace std::chrono;
using log_precision = microseconds;
constexpr auto den = log_precision::period::den;

/**
 * Print va_list to std::ostream (used for logging).
 */
void
printfLog(std::ostream& s, source_loc loc, std::string_view prefix, const std::string& message)
{
    auto num = duration_cast<log_precision>(steady_clock::now().time_since_epoch()).count();
    if (!loc.file.empty())
        fmt::print(s,
                   "[{:06d}.{:06d} {:>20}:{:<5} {:<24}] {}",
                   num / den,
                   num % den,
                   loc.file,
                   loc.line,
                   loc.function,
                   prefix);
    else
        fmt::print(s, "[{:06d}.{:06d}] {}", num / den, num % den, prefix);
    s << message << std::endl;
}

void
printLog(std::ostream& s, source_loc loc, std::string_view prefix, fmt::string_view format, fmt::format_args args)
{
    auto num = duration_cast<log_precision>(steady_clock::now().time_since_epoch()).count();
    fmt::print(s, "[{:06d}.{:06d}] {}", num / den, num % den, prefix);
    fmt::vprint(s, format, args);
    s << std::endl;
}

std::shared_ptr<Logger>
getStdLogger()
{
    return std::make_shared<Logger>([](source_loc loc, LogLevel level, std::string_view prefix, std::string&& message) {
        if (level == LogLevel::error)
            std::cerr << red;
        else if (level == LogLevel::warning)
            std::cerr << yellow;
        printfLog(std::cerr, loc, prefix, message);
        std::cerr << def;
    });
}

std::shared_ptr<Logger>
getFileLogger(const std::string& path)
{
    auto logfile = std::make_shared<std::ofstream>();
    logfile->open(path, std::ios::out);
    return std::make_shared<Logger>(
        [logfile](source_loc loc, LogLevel /*level*/, std::string_view prefix, std::string&& message) {
            printfLog(*logfile, loc, prefix, message);
        });
}

#ifndef _WIN32
constexpr int
syslogLevel(LogLevel level)
{
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
#endif

std::shared_ptr<Logger>
getSyslogLogger(const char* name)
{
#ifndef _WIN32
    struct Syslog
    {
        explicit Syslog(const char* n) { openlog(n, LOG_NDELAY, LOG_USER); }
        ~Syslog() { closelog(); }
    };
    // syslog is global. Existing instance must be reused.
    static std::weak_ptr<Syslog> opened_logfile;
    auto logfile = opened_logfile.lock();
    if (not logfile) {
        logfile = std::make_shared<Syslog>(name);
        opened_logfile = logfile;
    }
    return std::make_shared<Logger>(
        [logfile](source_loc loc, LogLevel level, std::string_view prefix, std::string&& message) {
            syslog(syslogLevel(level),
                   "%.*s%.*s",
                   (int) prefix.size(),
                   prefix.data(),
                   (int) message.size(),
                   message.c_str());
        });
#else
    return getStdLogger();
#endif
}

void
enableLogging(dht::DhtRunner& dht)
{
    dht.setLogger(getStdLogger());
}

void
enableFileLogging(dht::DhtRunner& dht, const std::string& path)
{
    dht.setLogger(getFileLogger(path));
}

OPENDHT_PUBLIC void
enableSyslog(dht::DhtRunner& dht, const char* name)
{
    dht.setLogger(getSyslogLogger(name));
}

void
disableLogging(dht::DhtRunner& dht)
{
    dht.setLogger();
}

} // namespace log
} // namespace dht
