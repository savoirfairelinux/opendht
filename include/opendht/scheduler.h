/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
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
        Job(std::function<void()>&& f) : do_(std::move(f)) {}
        std::function<void()> do_;
        void cancel() { do_ = {}; }
    };

    /**
     * Adds another job to the queue.
     *
     * @param time  The time upon which the job shall be executed.
     * @param job_func  The job function to execute.
     *
     * @return pointer to the newly scheduled job.
     */
    Sp<Scheduler::Job> add(time_point t, std::function<void()>&& job_func) {
        auto job = std::make_shared<Job>(std::move(job_func));
        if (t != time_point::max())
            timers.emplace(std::move(t), job);
        return job;
    }

    void add(const Sp<Scheduler::Job>& job, time_point t) {
        if (t != time_point::max())
            timers.emplace(std::move(t), job);
    }

    /**
     * Reschedules a job.
     *
     * @param job  The job to edit.
     * @param t  The time at which the job shall be rescheduled.
     */
    void edit(Sp<Scheduler::Job>& job, time_point t) {
        if (not job) {
            return;
        }
        // std::function move doesn't garantee to leave the object empty.
        // Force clearing old value.
        auto task = std::move(job->do_);
        job->do_ = {};
        job = add(t, std::move(task));
    }

    /**
     * Runs the jobs to do up to now.
     *
     * @return The time for the next job to run.
     */
    time_point run() {
        while (not timers.empty()) {
            auto timer = timers.begin();
            /*
             * Running jobs scheduled before "now" prevents run+rescheduling
             * loops before this method ends. It is garanteed by the fact that a
             * job will at least be scheduled for "now" and not before.
             */
            if (timer->first > now)
                break;

            auto job = std::move(timer->second);
            timers.erase(timer);

            if (job->do_)
                job->do_();
        }
        return getNextJobTime();
    }

    inline time_point getNextJobTime() const {
        return timers.empty() ? time_point::max() : timers.begin()->first;
    }

    /**
     * Accessors for the common time reference used for synchronizing
     * operations.
     */
    inline const time_point& time() const { return now; }
    inline time_point syncTime() { return (now = clock::now()); }
    inline void syncTime(const time_point& n) { now = n; }

private:
    time_point now {clock::now()};
    std::multimap<time_point, Sp<Job>> timers {}; /* the jobs ordered by time */
};

}
