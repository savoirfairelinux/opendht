// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "def.h"
#include "logger.h"

#include <iostream>
#include <memory>

namespace dht {

class DhtRunner;

/**
 * Logging-related functions
 */
namespace log {

OPENDHT_PUBLIC
std::shared_ptr<Logger> getStdLogger();

OPENDHT_PUBLIC
std::shared_ptr<Logger> getFileLogger(const std::string& path);

OPENDHT_PUBLIC
std::shared_ptr<Logger> getSyslogLogger(const char* name);

OPENDHT_PUBLIC void enableLogging(dht::DhtRunner& dht);

OPENDHT_PUBLIC void enableFileLogging(dht::DhtRunner& dht, const std::string& path);

OPENDHT_PUBLIC void disableLogging(dht::DhtRunner& dht);

OPENDHT_PUBLIC void enableSyslog(dht::DhtRunner& dht, const char* name);

} // namespace log
} // namespace dht
