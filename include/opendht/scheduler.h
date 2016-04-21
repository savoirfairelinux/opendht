/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <sim.desaulniers@gmail.com>
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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.
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
        time_point time;
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
        auto scheduled_time = std::max(time, now); /* This should prevent running an auto rescheduling job forever
                                                      before the Scheduler::run method ends. */
        auto job = std::make_shared<Job>(Job {false, false, scheduled_time, std::move(job_func)});
        timers.emplace(std::move(scheduled_time), job);
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
            /*
             * Running jobs scheduled before "now" prevents run+rescheduling
             * loops before this method ends. It is garanteed by the fact that a
             * job will at least be scheduled for "now" and not before.
             */
            if (not (timer->first < now))
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
