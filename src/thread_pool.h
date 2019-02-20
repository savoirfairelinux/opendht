/*
 *  Copyright (C) 2016-2019 Savoir-faire Linux Inc.
 *
 *  Author: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include <condition_variable>
#include <vector>
#include <queue>
#include <future>
#include <functional>

namespace dht {

class ThreadPool {
public:
    static ThreadPool& instance() {
        static ThreadPool pool;
        return pool;
    }

    ThreadPool();
    ThreadPool(size_t maxThreads);
    ~ThreadPool();

    void run(std::function<void()>&& cb);

    template<class T>
    std::future<T> get(std::function<T()>&& cb) {
        auto ret = std::make_shared<std::promise<T>>();
        run(std::bind([=](std::function<T()>& mcb) mutable {
                ret->set_value(mcb());
            }, std::move(cb)));
        return ret->get_future();
    }
    template<class T>
    std::shared_ptr<std::future<T>> getShared(std::function<T()>&& cb) {
        return std::make_shared<std::future<T>>(get(std::move(cb)));
    }

    void stop();
    void join();

private:
    struct ThreadState;
    std::queue<std::function<void()>> tasks_ {};
    std::vector<std::unique_ptr<ThreadState>> threads_;
    unsigned readyThreads_ {0};
    std::mutex lock_ {};
    std::condition_variable cv_ {};

    const unsigned maxThreads_;
    bool running_ {true};
};

}
