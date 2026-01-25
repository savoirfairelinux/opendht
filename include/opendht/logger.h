// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "infohash.h"

#include <fmt/format.h>
#include <fmt/printf.h>

#include <functional>
#include <string_view>
#include <type_traits>
#include <cstdarg>

#if __cplusplus >= 202002L
#include <source_location>
#endif

namespace dht {
namespace log {

#if __cplusplus >= 202002L
/**
 * Extracts the filename from a full file path at compile time.
 */
consteval std::string_view
getfilename(std::string_view path)
{
    size_t pos = path.size();
    for (size_t i = path.size(); i-- > 0;) {
        if (path[i] == '/' || path[i] == '\\') {
            pos = i + 1;
            break;
        }
    }
    return path.substr(pos);
}

consteval std::string_view
getfunctionname(std::string_view path)
{
    size_t pos = 0;
    size_t end = path.size();
    for (size_t i = 0; i < path.size(); i++) {
        if (path[i] == ' ' || path[i] == '\t' || path[i] == ':') {
            pos = i + 1;
        } else if (path[i] == '(') {
            end = i;
            break;
        }
    }
    return path.substr(pos, end - pos);
}
#endif

struct source_loc
{
    std::string_view file;
    std::uint_least32_t line;
    std::string_view function;

#if __cplusplus >= 202002L
    consteval source_loc(const std::source_location& loc)
        : file(getfilename(loc.file_name()))
        , line(loc.line())
        , function(getfunctionname(loc.function_name()))
    {}
#else
    constexpr source_loc()
        : file()
        , line(0)
        , function()
    {}
#endif
};

enum class LogLevel { debug, warning, error };

using LogMethod = std::function<void(source_loc, LogLevel, std::string_view, std::string&&)>;

template<typename... Args>
struct LogFormat
{
    fmt::format_string<Args...> fmt;
    source_loc loc;

#if __cplusplus >= 202002L
    template<typename S>
    consteval LogFormat(const S& s, const std::source_location& l = std::source_location::current())
        : fmt(s)
        , loc(l)
    {}
#else
    template<typename S>
    constexpr LogFormat(const S& s)
        : fmt(s)
        , loc()
    {}
#endif
};

#if __cplusplus < 202002L
template<class _Tp>
struct type_identity
{
    typedef _Tp type;
};
template<class _Tp>
using type_identity_t = typename type_identity<_Tp>::type;
#else
using std::type_identity_t;
#endif

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

    void setFilter(const InfoHash& f) { setFilter(f.to_view()); }

    inline void log0(source_loc loc, LogLevel level, fmt::string_view format, fmt::printf_args args) const
    {
        if (enable_)
            logger_(loc, level, prefix_, fmt::vsprintf(format, args));
    }
    template<typename... Args>
    inline void debug(LogFormat<type_identity_t<Args>...> format, Args&&... args) const
    {
        if (enable_)
            logger_(format.loc, LogLevel::debug, prefix_, fmt::format(format.fmt, std::forward<Args>(args)...));
    }
    template<typename... Args>
    inline void warn(LogFormat<type_identity_t<Args>...> format, Args&&... args) const
    {
        if (enable_)
            logger_(format.loc, LogLevel::warning, prefix_, fmt::format(format.fmt, std::forward<Args>(args)...));
    }
    template<typename... Args>
    inline void error(LogFormat<type_identity_t<Args>...> format, Args&&... args) const
    {
        if (enable_)
            logger_(format.loc, LogLevel::error, prefix_, fmt::format(format.fmt, std::forward<Args>(args)...));
    }
    template<typename... T>
    inline void d(LogFormat<type_identity_t<T>...> format, T&&... args) const
    {
        log0(format.loc, LogLevel::debug, format.fmt, fmt::make_printf_args(args...));
    }
    template<typename... T>
    inline void w(LogFormat<type_identity_t<T>...> format, T&&... args) const
    {
        log0(format.loc, LogLevel::warning, format.fmt, fmt::make_printf_args(args...));
    }
    template<typename... T>
    inline void e(LogFormat<type_identity_t<T>...> format, T&&... args) const
    {
        log0(format.loc, LogLevel::error, format.fmt, fmt::make_printf_args(args...));
    }

private:
    const LogMethod logger_ = {};
    const std::string tag_ {};
    const std::string prefix_ {};
    bool enable_ {true};
    std::vector<std::weak_ptr<Logger>> children_ {};
};

} // namespace log
using Logger = log::Logger;
} // namespace dht
