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
        bool done;
        bool cancelled;
        std::function<void()> do_;
    };

    /**
     * Adds another job to the queue.
     *
     * @param time  The time upon which the job shall be executed.
     * @param job_func  The job function to execute.
     *
     * @return pointer to the newly scheduled job.
     */
    std::shared_ptr<Scheduler::Job> add(time_point time, std::function<void()> job_func) {
        auto job = std::make_shared<Job>(Job {false, false, std::move(job_func)});
        timers.emplace(std::move(time), job);
        return job;
    }

    /**
     * Reschedules a job.
     *
     * @param time  The time at which the job shall be rescheduled.
     * @param job  The job to edit.
     *
     * @return pointer to the newly scheduled job.
     */
    std::shared_ptr<Scheduler::Job> edit(const std::shared_ptr<Scheduler::Job>& job, time_point time) {
        if (not job)
            return {};
        job->cancelled = true;
        return add(time, std::move(job->do_));
    }

    /**
     * Runs the jobs to do up to now.
     *
     * @return The time for the next job to run.
     */
    time_point run() {
        syncTime();
        while (not timers.empty()) {
            auto timer = timers.begin();
            if (timer->first > now)
                break;

            auto& job = timer->second;
            if (not job->cancelled and job->do_) {
                job->do_();
                job->done = true;
            }
            timers.erase(timer);
        }
        return getNextJobTime();
    }

    inline time_point getNextJobTime() const {
        return not timers.empty() ? timers.begin()->first : time_point::max();
    }

    /**
     * Accessors for the common time reference used for synchronizing
     * operations.
     */
    inline const time_point& time() const { return now; }
    inline time_point syncTime() { return (now = clock::now()); }

private:
    time_point now {clock::now()};
    std::multimap<time_point, std::shared_ptr<Job>> timers {}; /* the jobs ordered by time */
};

}
