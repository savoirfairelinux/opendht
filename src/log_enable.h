/*
 *  Copyright (C) 2016 Savoir-faire Linux Inc.
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
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef OPENDHT_LOG
#define OPENDHT_LOG true
#endif

#define DHT_LOG_DEBUG if (OPENDHT_LOG) DHT_LOG.DEBUG
#define DHT_LOG_WARN if (OPENDHT_LOG) DHT_LOG.WARN
#define DHT_LOG_ERR if (OPENDHT_LOG) DHT_LOG.ERR
