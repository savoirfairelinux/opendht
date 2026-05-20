// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_threadpool.h"

#include "opendht/thread_pool.h"
#include <atomic>
#include <thread>

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(ThreadPoolTester);
using clock = std::chrono::steady_clock;

void
ThreadPoolTester::setUp()
{}

void
ThreadPoolTester::testThreadPool()
{
    dht::ThreadPool pool(16);

    constexpr unsigned N = 64 * 1024;
    std::atomic_uint count {0};
    for (unsigned i = 0; i < N; i++)
        pool.run([&] { count++; });

    auto start = clock::now();
    while (count.load() != N && clock::now() - start < std::chrono::seconds(10))
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    pool.join();
    CPPUNIT_ASSERT_EQUAL(N, count.load());
}

void
ThreadPoolTester::testExecutor()
{
    dht::ThreadPool pool(8);
    auto executor1 = std::make_shared<dht::Executor>(pool, 1);
    auto executor4 = std::make_shared<dht::Executor>(pool, 4);
    auto executor8 = std::make_shared<dht::Executor>(pool, 8);

    constexpr unsigned N = 64 * 1024;
    unsigned count1 {0};
    std::atomic_uint count4 {0};
    std::atomic_uint count8 {0};
    for (unsigned i = 0; i < N; i++) {
        executor1->run([&] { count1++; });
        executor4->run([&] { count4++; });
        executor8->run([&] { count8++; });
    }

    auto start = clock::now();
    while ((count1 != N || count4.load() != N || count8.load() != N)
           && clock::now() - start < std::chrono::seconds(20)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    executor1.reset();
    executor4.reset();
    executor8.reset();
    CPPUNIT_ASSERT_EQUAL(N, count1);
    CPPUNIT_ASSERT_EQUAL(N, count4.load());
    CPPUNIT_ASSERT_EQUAL(N, count8.load());
}

void
ThreadPoolTester::testContext()
{
    std::atomic_uint count {0};
    constexpr unsigned N = 64 * 1024;

    {
        dht::ExecutionContext ctx(dht::ThreadPool::computation());
        for (unsigned i = 0; i < N; i++) {
            ctx.run([&] { count++; });
        }
    }

    CPPUNIT_ASSERT_EQUAL(N, count.load());
}

void
ThreadPoolTester::testJoinNonEmptyTaskQueue()
{
    dht::ThreadPool pool(2);

    constexpr unsigned N = 128;
    std::atomic_uint count {0};

    // Schedule enough work so that the task queue is non-empty when calling
    // pool.join() below.
    for (unsigned i = 0; i < N; i++)
        pool.run([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            count++;
        });

    std::atomic_bool joined {false};
    std::condition_variable cv;
    std::thread joinThread([&] {
        CPPUNIT_ASSERT(count.load() < N);
        pool.join();
        joined = true;
        cv.notify_one();
    });

    // After calling join(), all pending tasks should complete, and then all
    // threads in the pool should join.
    std::mutex mtx;
    std::unique_lock lock(mtx);
    bool poolJoined = cv.wait_for(lock, std::chrono::seconds(10), [&] { return joined.load(); });
    if (!poolJoined) {
        // Detach joinThread if we timed out, otherwise the test can crash.
        joinThread.detach();
    } else {
        joinThread.join();
    }
    CPPUNIT_ASSERT_EQUAL_MESSAGE("Some tasks were not completed", N, count.load());
    CPPUNIT_ASSERT_MESSAGE("Thread pool failed to join before timeout", poolJoined);
}

void
ThreadPoolTester::tearDown()
{}

} // namespace test
