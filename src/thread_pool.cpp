/*
 *  Copyright (C) 2014-2023 Savoir-faire Linux Inc.
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

#include "thread_pool.h"

#include <atomic>
#include <thread>
#include <iostream>
#include <ciso646> // fix windows compiler bug
#include <cmath> // std::pow

namespace dht {

constexpr const size_t IO_THREADS_MAX {512};

ThreadPool&
ThreadPool::computation()
{
    static ThreadPool pool;
    return pool;
}

ThreadPool&
ThreadPool::io()
{
    static ThreadPool pool(std::thread::hardware_concurrency(), IO_THREADS_MAX);
    return pool;
}


ThreadPool::ThreadPool(unsigned minThreads, unsigned maxThreads)
 : minThreads_(std::max(minThreads, 1u))
 , maxThreads_(maxThreads ? std::max(minThreads_, maxThreads) : minThreads_)
{
    threads_.reserve(maxThreads_);
    if (minThreads_ != maxThreads_) {
        threadDelayRatio_ = std::pow(3, 1.0 / (maxThreads_ - minThreads_));
    }
}

ThreadPool::ThreadPool()
 : ThreadPool(std::max(std::thread::hardware_concurrency(), 4u))
{}

ThreadPool::~ThreadPool()
{
    join();
}

void
ThreadPool::run(std::function<void()>&& cb)
{
    std::unique_lock<std::mutex> l(lock_);
    if (not cb or not running_) return;

    // launch new thread if necessary
    if (not readyThreads_ && threads_.size() < maxThreads_) {
        try {
            bool permanent_thread = threads_.size() < minThreads_;
            auto& thread = *threads_.emplace_back(std::make_unique<std::thread>());
            thread = std::thread([this, permanent_thread, e=threadExpirationDelay, &thread]() {
                while (true) {
                    std::function<void()> task;

                    // pick task from queue
                    {
                        std::unique_lock<std::mutex> l(lock_);
                        readyThreads_++;
                        auto waitCond = [&](){ return not running_ or not tasks_.empty(); };
                        if (permanent_thread)
                            cv_.wait(l, waitCond);
                        else 
                            cv_.wait_for(l, e, waitCond);
                        readyThreads_--;
                        if (not running_ or tasks_.empty())
                            break;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }

                    // run task
                    try {
                        task();
                    } catch (const std::exception& e) {
                        // LOG_ERR("Exception running task: %s", e.what());
                        std::cerr << "Exception running task: " << e.what() << std::endl;
                    }
                }
                if (not permanent_thread)
                    threadEnded(thread);
            });
        } catch(const std::exception& e) {
            std::cerr << "Exception starting thread: " << e.what() << std::endl;
            if (threads_.empty())
                throw;
        }
    }

    // push task to queue
    tasks_.emplace(std::move(cb));

    // notify thread
    cv_.notify_one();
}

void
ThreadPool::threadEnded(std::thread& thread)
{
    std::lock_guard<std::mutex> l(lock_);
    tasks_.emplace([this,t=std::reference_wrapper<std::thread>(thread)]{
        std::lock_guard<std::mutex> l(lock_);
        for (auto it = threads_.begin(); it != threads_.end(); ++it) {
            if (&*(*it) == &t.get()) {
                t.get().join();
                threads_.erase(it);
                break;
            }
        }
    });
    // A thread expired, maybe after handling a one-time burst of tasks.
    // If new threads start later, increase the expiration delay.
    if (threadExpirationDelay > std::chrono::hours(24 * 7)) {
        // If we reach 7 days, assume the thread is regularly used at full capacity
        minThreads_ = std::min(minThreads_+1, maxThreads_);
    } else {
        threadExpirationDelay *= threadDelayRatio_;
    }
    cv_.notify_one();
}

void
ThreadPool::stop(bool wait)
{
    std::unique_lock<std::mutex> l(lock_);
    if (wait) {
        cv_.wait(l, [&](){ return tasks_.empty(); });
    }
    running_ = false;
    tasks_ = {};
    cv_.notify_all();
}

void
ThreadPool::join()
{
    stop();
    for (auto& t : threads_)
        t->join();
    threads_.clear();
    tasks_ = {};
}

void
Executor::run(std::function<void()>&& task)
{
    std::lock_guard<std::mutex> l(lock_);
    if (current_ < maxConcurrent_) {
        run_(std::move(task));
    } else {
        tasks_.emplace(std::move(task));
    }
}

void
Executor::run_(std::function<void()>&& task)
{
    current_++;
    std::weak_ptr<Executor> w = shared_from_this();
    threadPool_.get().run([w,task = std::move(task)] {
        try {
            task();
        } catch (const std::exception& e) {
            std::cerr << "Exception running task: " << e.what() << std::endl;
        }
        if (auto sthis = w.lock()) {
            auto& this_ = *sthis;
            std::lock_guard<std::mutex> l(this_.lock_);
            this_.current_--;
            this_.schedule();
        }
    });
}

void
Executor::schedule()
{
    if (not tasks_.empty() and current_ < maxConcurrent_) {
        run_(std::move(tasks_.front()));
        tasks_.pop();
    }
}

}
