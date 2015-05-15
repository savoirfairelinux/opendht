#include "rng.h"

#include <cstring>

namespace dht {
namespace crypto {

void
random_device::cpuid_info(CPUIDinfo *info, const unsigned int func, const unsigned int subfunc)
{
    __asm__ __volatile__ (
            "cpuid"
            : "=a"(info->EAX), "=b"(info->EBX), "=c"(info->ECX), "=d"(info->EDX)
            : "a"(func), "c"(subfunc)
    );
}

bool
random_device::hasIntelCpu()
{
    CPUIDinfo info;
    cpuid_info(&info, 0, 0);
    if (memcmp((char *) (&info.EBX), "Genu", 4) == 0
     && memcmp((char *) (&info.EDX), "ineI", 4) == 0
     && memcmp((char *) (&info.ECX), "ntel", 4) == 0) {
        return true;
    }
    return false;
}

bool
random_device::hasRDRAND()
{
    if (!hasIntelCpu())
        return false;

    CPUIDinfo info;
    cpuid_info(&info, 1, 0);
    static const constexpr unsigned int RDRAND_FLAG = (1 << 30);
    if ((info.ECX & RDRAND_FLAG) == RDRAND_FLAG)
        return true;
    return false;
}

bool
random_device::RDRAND_bytes(uint8_t* buff, size_t bsize)
{
    if (!hasRDRAND())
        return false;

    size_t idx = 0, rem = bsize;
    size_t safety = bsize / sizeof(unsigned int) + 4;

    while (rem > 0 && safety > 0)
    {
        char rc;
        unsigned int val;

        __asm__ volatile(
                "rdrand %0 ; setc %1"
                : "=r" (val), "=qm" (rc)
        );

        // 1 = success, 0 = underflow
        if (rc) {
            size_t cnt = (rem < sizeof(val) ? rem : sizeof(val));
            memmove(buff + idx, &val, cnt);
            rem -= cnt;
            idx += cnt;
        } else {
            safety--;
		}
    }
    return !rem;
}

}}
