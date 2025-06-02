#include "def.h"
#include "infohash.h"

OPENDHT_PUBLIC extern const dht::HexMap hex_map;

dht::HexMap::HexMap() {
    for (size_t i = 0; i < size(); i++) {
        auto& e = (*this)[i];
        e[0] = hex_digits[(i >> 4) & 0x0F];
        e[1] = hex_digits[i & 0x0F];
    }
}
