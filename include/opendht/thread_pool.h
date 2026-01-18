// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "def.h"

#include <condition_variable>
#include <vector>
#include <queue>
#include <future>
#include <functional>

#include <ciso646> // fix windows compiler bug

namespace dht {

class OPENDHT_PUBLIC ThreadPool
{
public:
    static ThreadPool& computation();
    static ThreadPool& io();

    ThreadPool();
    ThreadPool(unsigned minThreads, unsigned maxThreads = 0);
    ~ThreadPool();

    void run(std::function<void()>&& cb);

    template<class T>
    std::future<T> get(std::function<T()>&& cb)
    {
        auto ret = std::make_shared<std::promise<T>>();
        run([cb = std::move(cb), ret]() mutable {
            try {
                ret->set_value(cb());
            } catch (...) {
                try {
                    ret->set_exception(std::current_exception());
                } catch (...) {
                }
            }
        });
        return ret->get_future();
    }
    template<class T>
    std::shared_future<T> getShared(std::function<T()>&& cb)
    {
        return get(std::move(cb));
    }

    void stop(bool wait = true);
    void join();
    void detach();

private:
    std::mutex lock_ {};
    std::condition_variable cv_ {};
    std::queue<std::function<void()>> tasks_ {};
    std::vector<std::unique_ptr<std::thread>> threads_;
    unsigned readyThreads_ {0};
    bool running_ {true};

    unsigned minThreads_;
    const unsigned maxThreads_;
    std::chrono::steady_clock::duration threadExpirationDelay {std::chrono::minutes(5)};
    double threadDelayRatio_ {2};

    void threadEnded(std::thread&);
};

class OPENDHT_PUBLIC Executor : public std::enable_shared_from_this<Executor>
{
public:
    Executor(ThreadPool& pool, unsigned maxConcurrent = 1)
        : threadPool_(pool)
        , maxConcurrent_(maxConcurrent)
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

class OPENDHT_PUBLIC ExecutionContext
{
public:
    ExecutionContext(ThreadPool& pool)
        : threadPool_(pool)
        , state_(std::make_shared<SharedState>())
    {}

    ~ExecutionContext() { state_->destroy(); }

    /** Wait for ongoing tasks to complete execution and drop other pending tasks */
    void stop() { state_->destroy(false); }

    void run(std::function<void()>&& task)
    {
        std::lock_guard<std::mutex> lock(state_->mtx);
        if (state_->shutdown_)
            return;
        state_->pendingTasks++;
        threadPool_.get().run([task = std::move(task), state = state_] { state->run(task); });
    }

private:
    struct SharedState
    {
        std::mutex mtx {};
        std::condition_variable cv {};
        unsigned pendingTasks {0};
        unsigned ongoingTasks {0};
        /** When true, prevents new tasks to be scheduled */
        bool shutdown_ {false};
        /** When true, prevents scheduled tasks to be executed */
        std::atomic_bool destroyed {false};

        void destroy(bool wait = true)
        {
            std::unique_lock<std::mutex> lock(mtx);
            if (destroyed)
                return;
            if (wait) {
                cv.wait(lock, [this] { return pendingTasks == 0 && ongoingTasks == 0; });
            }
            shutdown_ = true;
            if (not wait) {
                cv.wait(lock, [this] { return ongoingTasks == 0; });
            }
            destroyed = true;
        }

        void run(const std::function<void()>& task)
        {
            {
                std::lock_guard<std::mutex> lock(mtx);
                pendingTasks--;
                ongoingTasks++;
            }
            if (destroyed)
                return;
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

} // namespace dht
