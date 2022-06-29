/*
 *  Copyright (C) 2014-2022 Savoir-faire Linux Inc.
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

#include "apple_utils.h"

#ifdef __APPLE__
#include <Foundation/Foundation.h>
#include "TargetConditionals.h"
#endif

namespace dht {
namespace apple_utils {

std::string
getPlatformVersion() {
#ifdef __APPLE__
    #if TARGET_OS_IPHONE
    if (@available(iOS 14.5, *)) {
        return  "ios";
    }
    return "apple";
    #elif TARGET_OS_MAC
    return "macos";
    #endif
#endif
    return "";
}

}
} /* dht */
