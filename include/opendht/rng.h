#include <random>

namespace dht {
namespace crypto {

#ifdef _WIN32

class random_device {
public:
	using result_type = std::random_device::result_type;

	result_type operator()() {
		result_type bytes;
		RDRAND_bytes((uint8_t*)&bytes, sizeof(result_type));
		return bytes;
	}

	static constexpr result_type min() {
		return std::numeric_limits<result_type>::lowest();
	}
	static constexpr result_type max() {
		return std::numeric_limits<result_type>::max();
	}
	double entropy() const {
		if (hasRDRAND())
			return 1.;
		return 0.;
	}

private:
	random_device& operator=(random_device&) = delete;

	struct CPUIDinfo {
		unsigned int EAX;
		unsigned int EBX;
		unsigned int ECX;
		unsigned int EDX;
	};
	static void cpuid_info(CPUIDinfo *info, const unsigned int func, const unsigned int subfunc);
	static bool hasIntelCpu();
	static bool hasRDRAND();
	static bool RDRAND_bytes(uint8_t* buff, size_t bsize);
};

#else

using random_device = std::random_device;

#endif

}} // dht::crypto
