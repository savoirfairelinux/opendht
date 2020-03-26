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

#include "rng.h"

#include <chrono>
#include <cstring>

namespace dht {
namespace crypto {

random_device::random_device() :
   gen(std::chrono::system_clock::now().time_since_epoch().count() ^ std::chrono::high_resolution_clock::now().count())
{}

random_device::result_type
random_device::operator()()
{
    result_type prand = dis(gen);
    result_type hwrand;
    if (hasRdseed() and rdseed(&hwrand))
        prand ^= hwrand;
    else if (hasRdrand() and rdrand(&hwrand))
        prand ^= hwrand;
    return prand;
}

random_device::CPUIDinfo::CPUIDinfo(const unsigned int func, const unsigned int subfunc)
{
    __asm__ __volatile__ (
        "cpuid"
        : "=a"(EAX), "=b"(EBX), "=c"(ECX), "=d"(EDX)
        : "a"(func), "c"(subfunc)
    );
}

bool
random_device::hasIntelCpu()
{
    CPUIDinfo info (0, 0);
    return (memcmp((char *) (&info.EBX), "Genu", 4) == 0
         && memcmp((char *) (&info.EDX), "ineI", 4) == 0
         && memcmp((char *) (&info.ECX), "ntel", 4) == 0);
}

bool
random_device::_hasRdrand()
{
    return hasIntelCpu() && (CPUIDinfo {1, 0}.ECX & (1 << 30));
}

bool
random_device::_hasRdseed()
{
    return hasIntelCpu() && (CPUIDinfo {7, 0}.ECX & (1 << 18));
}

bool
random_device::rdrandStep(result_type* r)
{
    unsigned char ok;
    asm volatile ("rdrand %0; setc %1"
        : "=r" (*r), "=qm" (ok));
    return ok;
}

bool
random_device::rdrand(result_type* r)
{
    result_type res;
    unsigned retries = 8;
    while (retries--)
        if (rdrandStep(&res)) {
            *r = res;
            return true;
        }
    return false;
}

bool
random_device::rdseedStep(result_type* r)
{
    unsigned char ok;
    asm volatile ("rdseed %0; setc %1"
        : "=r" (*r), "=qm" (ok));
    return ok;
}

bool
random_device::rdseed(result_type* r)
{
    result_type res;
    unsigned retries = 256;
    while (retries--)
        if (rdseedStep(&res)) {
            *r = res;
            return true;
        }
    return false;
}

}}
