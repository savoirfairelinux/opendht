#include <random>

namespace dht {
namespace crypto {

#ifdef _WIN32

class random_device {
public:
    using result_type = std::random_device::result_type;
    using pseudo_engine = std::mt19937_64;

    /**
     * Current implementation assumption : result_type must be of a size
     * supported by Intel RDRAND/RDSEED.
     * result_type is unsigned int so this is currently safe.
     */
    static_assert(
        sizeof(result_type) == 2 || 
        sizeof(result_type) == 4 || 
        sizeof(result_type) == 8,
        "result_type must be 16, 32 or 64 bits");

    random_device();

    result_type operator()();

    static constexpr result_type min() {
        return std::numeric_limits<result_type>::lowest();
    }

    static constexpr result_type max() {
        return std::numeric_limits<result_type>::max();
    }

    double entropy() const {
        if (has_rdrand or has_rdseed)
            return 1.;
        return 0.;
    }

private:
    random_device& operator=(random_device&) = delete;

    const bool has_rdrand;
    const bool has_rdseed;
    pseudo_engine gen;
    std::uniform_int_distribution<result_type> dis {};

    struct CPUIDinfo {
        unsigned int EAX;
        unsigned int EBX;
        unsigned int ECX;
        unsigned int EDX;
        void get(const unsigned int func, const unsigned int subfunc);
    };
    static bool hasIntelCpu();
    static bool hasRdrand();
    static bool hasRdseed();
    bool rdrandStep(result_type* r);
    bool rdrand(result_type* r);
    bool rdseedStep(result_type* r);
    bool rdseed(result_type* r);
};

#else

using random_device = std::random_device;

#endif

}} // dht::crypto
