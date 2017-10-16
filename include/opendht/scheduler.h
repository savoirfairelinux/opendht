/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
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
#include "log_enable.h"
#include "uv_utils.h"

#include <uv.h>

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
    Scheduler(uv_loop_t* loop, const Logger& l) : loop_(loop), DHT_LOG(l) {}

    /**
     * Adds another job to the queue.
     *
     * @param time  The time upon which the job shall be executed.
     * @param job_func  The job function to execute.
     *
     * @return pointer to the newly scheduled job.
     */
    Sp<Job> add(const time_point& t, std::function<void()>&& job_func) {
        if (not loop_)
            return {};
        auto job = Job::make(loop_, std::move(job_func));
        if (t != time_point::max()) {
            garbageCollection();
            pending_jobs.emplace(job);
            job->run(t);
        } else
            job->cancel();
        return job;
    }
    Sp<Job> add(const duration& t, std::function<void()>&& job_func) {
        if (not loop_)
            return {};
        auto job = Job::make(loop_, std::move(job_func));
        garbageCollection();
        pending_jobs.emplace(job);
        job->run(t);
        return job;
    }
    Sp<Job> run(std::function<void()>&& job_func) {
        auto job = Job::make(loop_, std::move(job_func));
        garbageCollection();
        pending_jobs.emplace(job);
        job->run();
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
    void edit(Sp<Job>& job, const duration& t = {}) {
        if (not loop_)
            return;
        if (not job) {
            DHT_LOG.ERR("editing an empty job");
            return;
        }
        // std::function move doesn't garantee to leave the object empty.
        // Force clearing old value.
        auto task = std::move(job->do_);
        job->do_ = {};
        job->cancel();
        job = add(t, std::move(task));
    }
    void edit(Sp<Job>& job, const time_point& t) {
        if (not loop_)
            return;
        if (not job) {
            DHT_LOG.ERR("editing an empty job");
            return;
        }
        auto task = std::move(job->do_);
        job->do_ = {};
        job->cancel();
        job = add(t, std::move(task));
    }

    void stop() {
        loop_ = nullptr;
        size_t del {0};
        for (auto& w : pending_jobs)
            if (auto job = w.lock()) {
                job->cancel();
                del++;
            }
        pending_jobs.clear();
        DHT_LOG.DEBUG("stopping scheduler, %lu events canceled", del);
    }

    ~Scheduler(){
        stop();
    }

    /**
     * Accessors for the common time reference used for synchronizing
     * operations.
     */
    inline time_point time() const {
        return time_point(std::chrono::duration_cast<duration>(std::chrono::milliseconds(uv_now(loop_))));
    }
    inline time_point syncTime() {
        return time();
    }
    uv_loop_t* getLoop() const {
        return loop_;
    }

private:
    std::set<std::weak_ptr<Job>, std::owner_less<std::weak_ptr<Job>>> pending_jobs {};
    size_t lastSize_ {0};
    uv_loop_t* loop_;
    const Logger& DHT_LOG;

    void garbageCollection() {
        if (pending_jobs.size() > lastSize_ * 2) {
            unsigned del {0};
            for (auto it = pending_jobs.begin(); it != pending_jobs.end();) {
                if (it->expired()) {
                    it = pending_jobs.erase(it);
                    del++;
                } else 
                    ++it;
            }
            //DHT_LOG.DEBUG("pending_jobs cleanup: %u removed, %zu remaining", del, pending_jobs.size());
            lastSize_ = pending_jobs.size();
        }
    }

};

}
