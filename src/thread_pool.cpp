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

#include "thread_pool.h"

#include <atomic>
#include <thread>
#include <iostream>
#include <ciso646> // fix windows compiler bug

namespace dht {

constexpr const size_t IO_THREADS_MAX {64};

struct ThreadPool::ThreadState
{
    std::thread thread {};
    std::atomic_bool run {true};
};

ThreadPool&
ThreadPool::computation()
{
    static ThreadPool pool;
    return pool;
}

ThreadPool&
ThreadPool::io()
{
    static ThreadPool pool(IO_THREADS_MAX);
    return pool;
}


ThreadPool::ThreadPool(size_t maxThreads) : maxThreads_(maxThreads)
{
    threads_.reserve(maxThreads_);
}

ThreadPool::ThreadPool()
 : ThreadPool(std::max<size_t>(std::thread::hardware_concurrency(), 4))
{}

ThreadPool::~ThreadPool()
{
    join();
}

void
ThreadPool::run(std::function<void()>&& cb)
{
    std::unique_lock<std::mutex> l(lock_);
    if (not running_) return;

    // launch new thread if necessary
    if (not readyThreads_ && threads_.size() < maxThreads_) {
        threads_.emplace_back(new ThreadState());
        auto& t = *threads_.back();
        t.thread = std::thread([&]() {
            while (t.run) {
                std::function<void()> task;

                // pick task from queue
                {
                    std::unique_lock<std::mutex> l(lock_);
                    readyThreads_++;
                    cv_.wait(l, [&](){
                        return not t.run or not tasks_.empty();
                    });
                    readyThreads_--;
                    if (not t.run)
                        break;
                    task = std::move(tasks_.front());
                    tasks_.pop();
                }

                // run task
                try {
                    if (task)
                        task();
                } catch (const std::exception& e) {
                    // LOG_ERR("Exception running task: %s", e.what());
                    std::cerr << "Exception running task: " << e.what() << std::endl;
                }
            }
        });
    }

    // push task to queue
    tasks_.emplace(std::move(cb));

    // notify thread
    l.unlock();
    cv_.notify_one();
}

void
ThreadPool::stop()
{
    {
        std::lock_guard<std::mutex> l(lock_);
        running_ = false;
    }
    for (auto& t : threads_)
        t->run = false;
    cv_.notify_all();
}

void
ThreadPool::join()
{
    stop();
    for (auto& t : threads_)
        t->thread.join();
    threads_.clear();
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
    threadPool_.get().run([w,task] {
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
