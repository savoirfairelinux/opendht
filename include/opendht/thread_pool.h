/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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

#include "def.h"

#include <condition_variable>
#include <vector>
#include <queue>
#include <future>
#include <functional>

#include <ciso646> // fix windows compiler bug

namespace dht {

class OPENDHT_PUBLIC ThreadPool {
public:
    static ThreadPool& computation();
    static ThreadPool& io();

    ThreadPool();
    ThreadPool(size_t maxThreads);
    ~ThreadPool();

    void run(std::function<void()>&& cb);

    template<class T>
    std::future<T> get(std::function<T()>&& cb) {
        auto ret = std::make_shared<std::promise<T>>();
        run([cb = std::move(cb), ret]() mutable {
            try {
                ret->set_value(cb());
            } catch (...) {
                try {
                    ret->set_exception(std::current_exception());
                } catch(...) {}
            }
        });
        return ret->get_future();
    }
    template<class T>
    std::shared_future<T> getShared(std::function<T()>&& cb) {
        return get(std::move(cb));
    }

    void stop();
    void join();

private:
    std::mutex lock_ {};
    std::condition_variable cv_ {};
    std::queue<std::function<void()>> tasks_ {};
    std::vector<std::unique_ptr<std::thread>> threads_;
    unsigned readyThreads_ {0};
    bool running_ {true};

    const unsigned maxThreads_;
};

class OPENDHT_PUBLIC Executor : public std::enable_shared_from_this<Executor> {
public:
    Executor(ThreadPool& pool, unsigned maxConcurrent = 1)
     : threadPool_(pool), maxConcurrent_(maxConcurrent)
    {}

    void run(std::function<void()>&& task);

private:
    std::reference_wrapper<ThreadPool> threadPool_;
    const unsigned maxConcurrent_ {1};
    std::mutex lock_ {};
    unsigned current_ {0};
    std::queue<std::function<void()>> tasks_ {};

    void run_(std::function<void()>&& task);
    void schedule();
};

class OPENDHT_PUBLIC ExecutionContext {
public:
    ExecutionContext(ThreadPool& pool)
     : threadPool_(pool), state_(std::make_shared<SharedState>())
    {}

    ~ExecutionContext() {
        state_->destroy();
    }

    /** Wait for ongoing tasks to complete execution and drop other pending tasks */
    void stop() {
        state_->destroy(false);
    }

    void run(std::function<void()>&& task) {
        std::lock_guard<std::mutex> lock(state_->mtx);
        if (state_->shutdown_) return;
        state_->pendingTasks++;
        threadPool_.get().run([task = std::move(task), state = state_] {
            state->run(task);
        });
    }

private:
    struct SharedState {
        std::mutex mtx {};
        std::condition_variable cv {};
        unsigned pendingTasks {0};
        unsigned ongoingTasks {0};
        /** When true, prevents new tasks to be scheduled */
        bool shutdown_ {false};
        /** When true, prevents scheduled tasks to be executed */
        std::atomic_bool destroyed {false};

        void destroy(bool wait = true) {
            std::unique_lock<std::mutex> lock(mtx);
            if (destroyed) return;
            if (wait) {
                cv.wait(lock, [this] { return pendingTasks == 0 && ongoingTasks == 0; });
            }
            shutdown_ = true;
            if (not wait) {
                cv.wait(lock, [this] { return ongoingTasks == 0; });
            }
            destroyed = true;
        }

        void run(const std::function<void()>& task) {
            {
                std::lock_guard<std::mutex> lock(mtx);
                pendingTasks--;
                ongoingTasks++;
            }
                if (destroyed) return;
                task();
            {
                std::lock_guard<std::mutex> lock(mtx);
                ongoingTasks--;
                cv.notify_all();
            }
        }
    };
    std::reference_wrapper<ThreadPool> threadPool_;
    std::shared_ptr<SharedState> state_;
};

}
