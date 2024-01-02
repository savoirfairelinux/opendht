/*
 *  Copyright (C) 2014-2023 Savoir-faire Linux Inc.
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

#include <vector>
#include <random>

namespace dht {
namespace crypto {

template <class T>
class secure_vector
{
public:
    secure_vector() {}
    secure_vector(secure_vector<T> const&) = default;
    secure_vector(secure_vector<T> &&) = default;
    explicit secure_vector(unsigned size): data_(size) {}
    explicit secure_vector(unsigned size, T _item): data_(size, _item) {}
    explicit secure_vector(const std::vector<T>& c): data_(c) {}
    secure_vector(std::vector<T>&& c): data_(std::move(c)) {}
    ~secure_vector() { clean(); }

    static secure_vector<T> getRandom(size_t size) {
        secure_vector<T> ret(size);
        std::random_device rdev;
#ifdef _WIN32
        std::uniform_int_distribution<int> rand_byte{ 0, std::numeric_limits<uint8_t>::max() };
#else
        std::uniform_int_distribution<uint8_t> rand_byte;
#endif
        std::generate_n((uint8_t*)ret.data_.data(), ret.size()*sizeof(T), std::bind(rand_byte, std::ref(rdev)));
        return ret;
    }
    secure_vector<T>& operator=(const secure_vector<T>& c) {
        if (&c == this)
            return *this;
        clean();
        data_ = c.data_;
        return *this;
    }
    secure_vector<T>& operator=(secure_vector<T>&& c) {
        if (&c == this)
            return *this;
        clean();
        data_ = std::move(c.data_);
        return *this;
    }
    secure_vector<T>& operator=(std::vector<T>&& c) {
        clean();
        data_ = std::move(c);
        return *this;
    }
    std::vector<T>& writable() { clean(); return data_; }
    const std::vector<T>& makeInsecure() const { return data_; }
    const uint8_t* data() const { return data_.data(); }

    void clean() {
        clean(data_.begin(), data_.end());
    }

    void clear() { clean(); data_.clear(); }

    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    void swap(secure_vector<T>& other) { data_.swap(other.data_); }
    void resize(size_t s) {
        if (s == data_.size()) return;
        if (s < data_.size()) {
            //shrink
            clean(data_.begin()+s, data_.end());
            data_.resize(s);
        } else {
            //grow
            auto data = std::move(data_); // move protected data
            clear();
            data_.resize(s);
            std::copy(data.begin(), data.end(), data_.begin());
            clean(data.begin(), data.end());
        }
    }

private:
    /**
     * Securely wipe memory
     */
    static void clean(const typename std::vector<T>::iterator& i, const typename std::vector<T>::iterator& j) {
        volatile uint8_t* b = reinterpret_cast<uint8_t*>(&*i);
        volatile uint8_t* e = reinterpret_cast<uint8_t*>(&*j);
        std::fill(b, e, 0);
    }

    std::vector<T> data_;
};

using SecureBlob = secure_vector<uint8_t>;

}
}
