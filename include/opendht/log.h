/*
 *  Copyright (c) 2014-2026 Savoir-faire Linux Inc.
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
std::shared_ptr<Logger> getFileLogger(const std::string &path);

OPENDHT_PUBLIC
std::shared_ptr<Logger> getSyslogLogger(const char* name);

OPENDHT_PUBLIC void
enableLogging(dht::DhtRunner &dht);

OPENDHT_PUBLIC void
enableFileLogging(dht::DhtRunner &dht, const std::string &path);

OPENDHT_PUBLIC void
disableLogging(dht::DhtRunner &dht);

OPENDHT_PUBLIC void
enableSyslog(dht::DhtRunner &dht, const char* name);

} /* log */
} /* dht  */
