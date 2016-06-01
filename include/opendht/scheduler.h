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
        Job(std::function<void()>&& f) : do_(std::forward<std::function<void()>>(f)) {}
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
    std::shared_ptr<Scheduler::Job> add(time_point t, std::function<void()>&& job_func) {
        auto job = std::make_shared<Job>(std::forward<std::function<void()>>(job_func));
        if (t != time_point::max())
            timers.emplace(std::move(t), job);
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
    void edit(std::shared_ptr<Scheduler::Job>& job, time_point t) {
        if (not job) {
            std::cerr << "editing an empty job" << std::endl;
            return;
        }
        job = add(t, std::move(job->do_));
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
            if (timer->first > now)
                break;

            const auto& job = *timer->second;
            if (job.do_)
                job.do_();
            timers.erase(timer);
        }
        return getNextJobTime();
    }

    inline time_point getNextJobTime() const {
        //if (not timers.empty())
        //    std::cout << "Next job in " << print_dt(timers.begin()->first - clock::now()) << std::endl;
        return timers.empty() ? time_point::max() : timers.begin()->first;
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
