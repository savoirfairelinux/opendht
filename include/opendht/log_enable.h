/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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

#include <cstdarg>

#ifndef OPENDHT_LOG
#define OPENDHT_LOG true
#endif

namespace dht {

// Logging related utility functions

/**
 * Wrapper for logging methods
 */
struct LogMethod {
    LogMethod() = default;

    LogMethod(LogMethod&& l) : func(std::move(l.func)) {}
    LogMethod(const LogMethod& l) : func(l.func) {}

    LogMethod& operator=(dht::LogMethod&& l) {
        func = std::forward<LogMethod>(l.func);
        return *this;
    }
    LogMethod& operator=(const dht::LogMethod& l) {
        func = l.func;
        return *this;
    }

    template<typename T>
    explicit LogMethod(T&& t) : func(std::forward<T>(t)) {}

    template<typename T>
    LogMethod(const T& t) : func(t) {}

    void operator()(char const* format, ...) const {
        va_list args;
        va_start(args, format);
        func(format, args);
        va_end(args);
    }
    inline void log(char const* format, va_list args) const {
        func(format, args);
    }
    explicit operator bool() const {
        return (bool)func;
    }

    void logPrintable(const uint8_t *buf, size_t buflen) const {
        std::string buf_clean(buflen, '\0');
        for (size_t i=0; i<buflen; i++)
            buf_clean[i] = isprint(buf[i]) ? buf[i] : '.';
        (*this)("%s", buf_clean.c_str());
    }
private:
    std::function<void(char const*, va_list)> func;
};

struct Logger {
    LogMethod DBG = {};
    LogMethod WARN = {};
    LogMethod ERR = {};

    Logger() = default;
    Logger(LogMethod&& err, LogMethod&& warn, LogMethod&& dbg)
        : DBG(std::move(dbg)), WARN(std::move(warn)), ERR(std::move(err)) {}
    void setFilter(const InfoHash& f) {
        filter_ = f;
        filterEnable_ = static_cast<bool>(filter_);
    }
    inline void log0(const LogMethod& logger, char const* format, va_list args) const {
#if OPENDHT_LOG
        if (logger and not filterEnable_)
            logger.log(format, args);
#endif
    }
    inline void log1(const LogMethod& logger, const InfoHash& f, char const* format, va_list args) const {
#if OPENDHT_LOG
        if (logger and (not filterEnable_ or f == filter_))
            logger.log(format, args);
#endif
    }
    inline void log2(const LogMethod& logger, const InfoHash& f1, const InfoHash& f2, char const* format, va_list args) const {
#if OPENDHT_LOG
        if (logger and (not filterEnable_ or f1 == filter_ or f2 == filter_))
            logger.log(format, args);
#endif
    }
    inline void d(char const* format, ...) const {
#if OPENDHT_LOG
        va_list args;
        va_start(args, format);
        log0(DBG, format, args);
        va_end(args);
#endif
    }
    inline void d(const InfoHash& f, char const* format, ...) const {
#if OPENDHT_LOG
        va_list args;
        va_start(args, format);
        log1(DBG, f, format, args);
        va_end(args);
#endif
    }
    inline void d(const InfoHash& f1, const InfoHash& f2, char const* format, ...) const {
#if OPENDHT_LOG
        va_list args;
        va_start(args, format);
        log2(DBG, f1, f2, format, args);
        va_end(args);
#endif
    }
    inline void w(char const* format, ...) const {
#if OPENDHT_LOG
        va_list args;
        va_start(args, format);
        log0(WARN, format, args);
        va_end(args);
#endif
    }
    inline void w(const InfoHash& f, char const* format, ...) const {
#if OPENDHT_LOG
        va_list args;
        va_start(args, format);
        log1(WARN, f, format, args);
        va_end(args);
#endif
    }
    inline void w(const InfoHash& f1, const InfoHash& f2, char const* format, ...) const {
#if OPENDHT_LOG
        va_list args;
        va_start(args, format);
        log2(WARN, f1, f2, format, args);
        va_end(args);
#endif
    }
    inline void e(char const* format, ...) const {
#if OPENDHT_LOG
        va_list args;
        va_start(args, format);
        log0(ERR, format, args);
        va_end(args);
#endif
    }
    inline void e(const InfoHash& f, char const* format, ...) const {
#if OPENDHT_LOG
        va_list args;
        va_start(args, format);
        log1(ERR, f, format, args);
        va_end(args);
#endif
    }
    inline void e(const InfoHash& f1, const InfoHash& f2, char const* format, ...) const {
#if OPENDHT_LOG
        va_list args;
        va_start(args, format);
        log2(ERR, f1, f2, format, args);
        va_end(args);
#endif
    }
private:
    bool filterEnable_ {false};
    InfoHash filter_ {};
};

}
