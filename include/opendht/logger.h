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

#include "infohash.h"

#include <fmt/format.h>
#include <fmt/printf.h>

#include <functional>
#include <string_view>
#include <cstdarg>

namespace dht {
namespace log {

enum class LogLevel {
    debug, warning, error
};

using LogMethod = std::function<void(LogLevel, std::string&&)>;

struct Logger {
    LogMethod logger = {};

    Logger() = delete;
    Logger(LogMethod&& l)
        : logger(std::move(l)) {
            if (!logger)
                throw std::invalid_argument{"logger and loggerf must be set"};
        }
    void setFilter(const InfoHash& f) {
        filter_ = f;
        filterEnable_ = static_cast<bool>(filter_);
    }
    inline void log0(LogLevel level, fmt::string_view format, fmt::printf_args args) const {
        if (not filterEnable_)
            logger(level, fmt::vsprintf(format, args));
    }
    inline void log1(LogLevel level, const InfoHash& f, fmt::string_view format, fmt::printf_args args) const {
        if (not filterEnable_ or f == filter_)
            logger(level, fmt::vsprintf(format, args));
    }
    inline void log2(LogLevel level, const InfoHash& f1, const InfoHash& f2, fmt::string_view format, fmt::printf_args args) const {
        if (not filterEnable_ or f1 == filter_ or f2 == filter_)
            logger(level, fmt::vsprintf(format, args));
    }
    template<typename S, typename... Args>
    inline void debug(S&& format, Args&&... args) const {
        logger(LogLevel::debug, fmt::format(format, args...));
    }
    template<typename S, typename... Args>
    inline void warn(S&& format, Args&&... args) const {
        logger(LogLevel::warning, fmt::format(format, args...));
    }
    template<typename S, typename... Args>
    inline void error(S&& format, Args&&... args) const {
        logger(LogLevel::error, fmt::format(format, args...));
    }
    template <typename... T>
    inline void d(fmt::format_string<T...> format, T&&... args) const {
        log0(LogLevel::debug, format, fmt::make_printf_args(args...));
    }
    template <typename... T>
    inline void d(const InfoHash& f, fmt::format_string<T...> format, T&&... args) const {
        log1(LogLevel::debug, f, format, fmt::make_printf_args(args...));
    }
    template <typename... T>
    inline void d(const InfoHash& f1, const InfoHash& f2, fmt::format_string<T...> format, T&&... args) const {
        log2(LogLevel::debug, f1, f2, format, fmt::make_printf_args(args...));
    }
    template <typename... T>
    inline void w(fmt::format_string<T...> format, T&&... args) const {
        log0(LogLevel::warning, format, fmt::make_printf_args(args...));
    }
    template <typename... T>
    inline void w(const InfoHash& f, fmt::format_string<T...> format, T&&... args) const {
        log1(LogLevel::warning, f, format, fmt::make_printf_args(args...));
    }
    template <typename... T>
    inline void w(const InfoHash& f1, const InfoHash& f2, fmt::format_string<T...> format, T&&... args) const {
        log2(LogLevel::warning, f1, f2, format, fmt::make_printf_args(args...));
    }
    template <typename... T>
    inline void e(fmt::format_string<T...> format, T&&... args) const {
        log0(LogLevel::error, format, fmt::make_printf_args(args...));
    }
    template <typename... T>
    inline void e(const InfoHash& f, fmt::format_string<T...> format, T&&... args) const {
        log1(LogLevel::error, f, format, fmt::make_printf_args(args...));
    }
    template <typename... T>
    inline void e(const InfoHash& f1, const InfoHash& f2, fmt::format_string<T...> format, T&&... args) const {
        log2(LogLevel::error, f1, f2, format, fmt::make_printf_args(args...));
    }
private:
    bool filterEnable_ {false};
    InfoHash filter_ {};
};

}
using Logger = log::Logger;
}
