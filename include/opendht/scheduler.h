/*
Copyright (C) 2009-2014 Juliusz Chroboczek
Copyright (C) 2014-2016 Savoir-faire Linux Inc.

Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>,
            Simon Désaulniers <sim.desaulniers@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#pragma once

#include "utils.h"

#include <functional>
#include <map>

namespace dht {

/*!
 * @class   Scheduler
 * @brief   Job scheduler
 * @details
 * Maintains the timings upon which to execute a job.
 */
class Scheduler {
public:
    struct Job {
        bool canceled;
        std::function<void()> do_;
    };

    /**
     * Adds another job to the queue.
     *
     * @param time  The time upon which the job shall be executed.
     * @param job_func  The job function to execute.
     */
    std::weak_ptr<Scheduler::Job>
    add(time_point time, std::function<void()> job_func) {
        auto job = std::make_shared<Job>(Job {false, std::move(job_func)});
        timers.emplace(std::move(time), job);
        return job;
    }

    /**
     * Runs the jobs to do up to now.
     *
     * @return The time reference to "now".
     */
    time_point run() {
        now = clock::now();
        for (auto t = timers.begin(); t != timers.end(); ) {
            if (t->first > now)
                return now;
            t->second->do_();
            t = timers.erase(t);
        }
        return now;
    }

    inline time_point getNextJobTime() { return timers.begin()->first; }

    /**
     * Accessors for the common time reference used for synchronizing
     * operations.
     */
    inline time_point time() const { return now; }

private:
    time_point now {time_point::min()};
    std::multimap<time_point, std::shared_ptr<Job>> timers {}; /* the jobs ordered by time */
};

}
