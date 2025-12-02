/*
 *  Copyright (C) 2014-2025 Savoir-faire Linux Inc.
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

enum class LogLevel { debug, warning, error };

using LogMethod = std::function<void(LogLevel, std::string_view, std::string&&)>;

struct OPENDHT_PUBLIC Logger
{
    Logger() = delete;
    Logger(LogMethod&& l, std::string tag = "")
        : logger_(std::move(l))
        , tag_(std::move(tag))
        , prefix_(tag_.empty() ? "" : fmt::format("[{}] ", tag_))
    {
        if (!logger_)
            throw std::invalid_argument {"logger must be set"};
    }
    Logger(const Logger& parent, std::string tag)
        : logger_(parent.logger_)
        , tag_(std::move(tag))
        , prefix_(fmt::format("{}[{}] ", parent.prefix_, tag_))
    {}

    std::shared_ptr<Logger> createChild(std::string tag)
    {
        auto child = std::make_shared<Logger>(*this, std::move(tag));
        children_.push_back(child);
        return child;
    }

    void setFilter(std::string_view tag)
    {
        enable_ = tag.empty() or tag_ == tag;
        for (auto it = children_.begin(); it != children_.end();) {
            if (auto c = it->lock()) {
                c->setFilter(enable_ ? std::string_view {} : tag);
                ++it;
            } else {
                it = children_.erase(it);
            }
        }
    }

    void setFilter(const InfoHash& f)
    {
        filter_ = f;
        filterEnable_ = static_cast<bool>(filter_);
    }
    inline void log0(LogLevel level, fmt::string_view format, fmt::printf_args args) const
    {
        if (enable_ and not filterEnable_)
            logger_(level, prefix_, fmt::vsprintf(format, args));
    }
    inline void log1(LogLevel level, const InfoHash& f, fmt::string_view format, fmt::printf_args args) const
    {
        if (enable_ and (not filterEnable_ or f == filter_))
            logger_(level, prefix_, fmt::vsprintf(format, args));
    }
    inline void log2(
        LogLevel level, const InfoHash& f1, const InfoHash& f2, fmt::string_view format, fmt::printf_args args) const
    {
        if (enable_ and (not filterEnable_ or f1 == filter_ or f2 == filter_))
            logger_(level, prefix_, fmt::vsprintf(format, args));
    }
    template<typename... Args>
    inline void debug(fmt::format_string<Args...> format, Args&&... args) const
    {
        if (enable_)
            logger_(LogLevel::debug, prefix_, fmt::format(format, std::forward<Args>(args)...));
    }
    template<typename... Args>
    inline void warn(fmt::format_string<Args...> format, Args&&... args) const
    {
        if (enable_)
            logger_(LogLevel::warning, prefix_, fmt::format(format, std::forward<Args>(args)...));
    }
    template<typename... Args>
    inline void error(fmt::format_string<Args...> format, Args&&... args) const
    {
        if (enable_)
            logger_(LogLevel::error, prefix_, fmt::format(format, std::forward<Args>(args)...));
    }
    template<typename... T>
    inline void d(fmt::format_string<T...> format, T&&... args) const
    {
        log0(LogLevel::debug, format, fmt::make_printf_args(args...));
    }
    template<typename... T>
    inline void d(const InfoHash& f, fmt::format_string<T...> format, T&&... args) const
    {
        log1(LogLevel::debug, f, format, fmt::make_printf_args(args...));
    }
    template<typename... T>
    inline void d(const InfoHash& f1, const InfoHash& f2, fmt::format_string<T...> format, T&&... args) const
    {
        log2(LogLevel::debug, f1, f2, format, fmt::make_printf_args(args...));
    }
    template<typename... T>
    inline void w(fmt::format_string<T...> format, T&&... args) const
    {
        log0(LogLevel::warning, format, fmt::make_printf_args(args...));
    }
    template<typename... T>
    inline void w(const InfoHash& f, fmt::format_string<T...> format, T&&... args) const
    {
        log1(LogLevel::warning, f, format, fmt::make_printf_args(args...));
    }
    template<typename... T>
    inline void w(const InfoHash& f1, const InfoHash& f2, fmt::format_string<T...> format, T&&... args) const
    {
        log2(LogLevel::warning, f1, f2, format, fmt::make_printf_args(args...));
    }
    template<typename... T>
    inline void e(fmt::format_string<T...> format, T&&... args) const
    {
        log0(LogLevel::error, format, fmt::make_printf_args(args...));
    }
    template<typename... T>
    inline void e(const InfoHash& f, fmt::format_string<T...> format, T&&... args) const
    {
        log1(LogLevel::error, f, format, fmt::make_printf_args(args...));
    }
    template<typename... T>
    inline void e(const InfoHash& f1, const InfoHash& f2, fmt::format_string<T...> format, T&&... args) const
    {
        log2(LogLevel::error, f1, f2, format, fmt::make_printf_args(args...));
    }

private:
    const LogMethod logger_ = {};
    const std::string tag_ {};
    const std::string prefix_ {};
    bool enable_ {true};
    bool filterEnable_ {false};
    InfoHash filter_ {};
    std::vector<std::weak_ptr<Logger>> children_ {};
};

} // namespace log
using Logger = log::Logger;
} // namespace dht
