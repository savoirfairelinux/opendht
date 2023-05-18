/*
 *  Copyright (C) 2014-2022 Savoir-faire Linux Inc.
 *  Author : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "infohash.h"

#include <functional>
#include <string_view>
#include <cstdarg>

#ifndef OPENDHT_LOG
#define OPENDHT_LOG true
#endif

#include <fmt/format.h>
#include <fmt/printf.h>

namespace dht {
namespace log {

enum class LogLevel {
    debug, warning, error
};

using LogMethodFmt = std::function<void(LogLevel, fmt::string_view, fmt::format_args)>;
using LogMethodPrintf = std::function<void(LogLevel, fmt::string_view, fmt::printf_args)>;

struct Logger {
    LogMethodFmt logger = {};
    LogMethodPrintf loggerf = {};

    Logger() = default;
    Logger(LogMethodFmt&& logger, LogMethodPrintf&& loggerf)
        : logger(std::move(logger)), loggerf(std::move(loggerf)) {}
    void setFilter(const InfoHash& f) {
        filter_ = f;
        filterEnable_ = static_cast<bool>(filter_);
    }
    inline void logfmt(LogLevel level, fmt::string_view format, fmt::format_args args) {
        if (logger and not filterEnable_)
            logger(level, format, args);
    }
    inline void log0(LogLevel level, fmt::string_view format, fmt::printf_args args) const {
#if OPENDHT_LOG
        if (loggerf and not filterEnable_)
            loggerf(level, format, args);
#endif
    }
    inline void log1(LogLevel level, const InfoHash& f, fmt::string_view format, fmt::printf_args args) const {
#if OPENDHT_LOG
        if (loggerf and (not filterEnable_ or f == filter_))
            loggerf(level, format, args);
#endif
    }
    inline void log2(LogLevel level, const InfoHash& f1, const InfoHash& f2, fmt::string_view format, fmt::printf_args args) const {
#if OPENDHT_LOG
        if (loggerf and (not filterEnable_ or f1 == filter_ or f2 == filter_))
            loggerf(level, format, args);
#endif
    }
    template <typename... T>
    inline void debug(fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        logFmt(LogLevel::debug, format, fmt::make_format_args(args...));
#endif
    }
    template <typename... T>
    inline void warn(fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        logFmt(LogLevel::warning, format, fmt::make_format_args(args...));
#endif
    }
    template <typename... T>
    inline void error(fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        logFmt(LogLevel::error, format, fmt::make_format_args(args...));
#endif
    }
    template <typename... T>
    inline void d(fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        log0(LogLevel::debug, format, fmt::make_printf_args(args...));
#endif
    }
    template <typename... T>
    inline void d(const InfoHash& f, fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        log1(LogLevel::debug, f, format, fmt::make_printf_args(args...));
#endif
    }
    template <typename... T>
    inline void d(const InfoHash& f1, const InfoHash& f2, fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        log2(LogLevel::debug, f1, f2, format, fmt::make_printf_args(args...));
#endif
    }
    template <typename... T>
    inline void w(fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        log0(LogLevel::warning, format, fmt::make_printf_args(args...));
#endif
    }
    template <typename... T>
    inline void w(const InfoHash& f, fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        log1(LogLevel::warning, f, format, fmt::make_printf_args(args...));
#endif
    }
    template <typename... T>
    inline void w(const InfoHash& f1, const InfoHash& f2, fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        log2(LogLevel::warning, f1, f2, format, fmt::make_printf_args(args...));
#endif
    }
    template <typename... T>
    inline void e(fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        log0(LogLevel::error, format, fmt::make_printf_args(args...));
#endif
    }
    template <typename... T>
    inline void e(const InfoHash& f, fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        log1(LogLevel::error, f, format, fmt::make_printf_args(args...));
#endif
    }
    template <typename... T>
    inline void e(const InfoHash& f1, const InfoHash& f2, fmt::format_string<T...> format, T&&... args) const {
#if OPENDHT_LOG
        log2(LogLevel::error, f1, f2, format, fmt::make_printf_args(args...));
#endif
    }
private:
    bool filterEnable_ {false};
    InfoHash filter_ {};
};

}
using Logger = log::Logger;
}
