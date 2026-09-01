/** Credits to Jakob Progsch (@progschj)
 https://github.com/progschj/thread_pool
 Copyright (c) 2012 Jakob Progsch, Václav Zeman
 This software is provided 'as-is', without any express or implied
 warranty. In no event will the authors be held liable for any damages
 arising from the use of this software.
 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:
 1. The origin of this software must not be misrepresented; you must not
 claim that you wrote the original software. If you use this software
 in a product, an acknowledgment in the product documentation would be
 appreciated but is not required.
 2. Altered source versions must be plainly marked as such, and must not be
 misrepresented as being the original software.
 3. This notice may not be removed or altered from any source
 distribution.
 Modified by teble at LuckyPray, 2022.
*/

#pragma once

#include <vector>
#include <queue>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <stdexcept>

#include "matcher_thread_cache_registry.h"

class ThreadPool {
public:
    explicit ThreadPool(size_t, std::function<bool()> should_skip_task = {});

    template<class F, class... Args>
    auto enqueue(F &&f, Args &&... args)
    -> std::future<typename std::invoke_result<F, Args...>::type>;

    ~ThreadPool();

private:
    // dexllm(#50): everything a worker touches lives in State, which is owned by
    // shared_ptr and therefore OUTLIVES the ThreadPool object.
    //
    // A pool task can hold the last reference to its own pool (in DexKit a task
    // holds the last shared_ptr<QueryScheduler>, and the scheduler owns the
    // pool), so ~ThreadPool can run ON one of its own workers. It cannot join
    // the thread it is executing on — std::thread::join() throws
    // std::system_error "Resource deadlock avoided", uncaught in a thread, which
    // terminates the process. The destructor detaches that one worker instead;
    // the worker's loop then reads only State, which its own reference keeps
    // alive, so the detach is not a use-after-free.
    struct State {
        // the task queue
        std::queue<std::function<void()> > tasks;
        // synchronization
        std::mutex queue_mutex;
        std::condition_variable condition;
        bool stop = false;
        std::function<bool()> should_skip_task;
    };

    std::shared_ptr<State> state_;
    // need to keep track of threads so we can join them
    std::vector<std::thread> workers;
};

// the constructor just launches some amount of workers
inline ThreadPool::ThreadPool(size_t threads, std::function<bool()> should_skip_task)
        : state_(std::make_shared<State>()) {
    state_->should_skip_task = std::move(should_skip_task);
#if defined(__EMSCRIPTEN__) && !defined(__EMSCRIPTEN_PTHREADS__)
    // dexllm: non-pthread WASM (GitHub Pages can't ship COOP/COEP for
    // SharedArrayBuffer).
    // std::thread's ctor throws "Not supported" here, which kills every APK load
    // path that uses multi-image AddImage. Run tasks inline instead — `enqueue`
    // drains the queue from the calling thread, so the future resolves before
    // the caller waits on it.
    (void)threads;
#else
    workers.reserve(threads);
    // dexllm(#50): the worker captures `state` and NOT `this`, so nothing it
    // touches can be freed out from under it when the pool is destroyed. It no
    // longer records its own id either — the destructor reads the ids off the
    // `std::thread` objects, which is both race-free and, unlike a slot the
    // worker fills in itself, already correct before the worker has started.
    //
    // dexllm(#55): the spawn loop is wrapped because `std::thread`'s constructor
    // THROWS when the process is out of threads (EAGAIN under RLIMIT_NPROC or a
    // container pids limit). Unwinding out of a partially built pool destroys a
    // still-JOINABLE `std::thread`, which is `std::terminate()` — the process
    // dies before any caller's catch runs, which silently voided the recovery
    // path InitDexCache builds on this scope being catchable. Reproduced with a
    // real RLIMIT_NPROC: failing the FIRST thread was already survivable
    // (nothing was built yet), failing the SECOND aborted, and 2+ threads is the
    // normal configuration for a multi-dex source.
    try {
        for (size_t i = 0; i < threads; ++i)
            workers.emplace_back(
                    [state = state_] {
                        for (;;) {
                            std::function<void()> task;

                            {
                                std::unique_lock lock(state->queue_mutex);
                                state->condition.wait(lock, [&state] { return state->stop || !state->tasks.empty(); });
                                if (state->stop && state->tasks.empty())
                                    return;
                                task = std::move(state->tasks.front());
                                state->tasks.pop();
                            }

                            task();
                        }
                    }
            );
    } catch (...) {
        {
            std::unique_lock lock(state_->queue_mutex);
            state_->stop = true;
        }
        state_->condition.notify_all();
        for (std::thread &worker: workers) {
            if (worker.joinable()) worker.join();
        }
        workers.clear();
        throw;
    }
#endif
}

// add new work item to the pool
template<class F, class... Args>
auto ThreadPool::enqueue(F &&f, Args &&... args)
-> std::future<typename std::invoke_result<F, Args...>::type> {
    using return_type = typename std::invoke_result<F, Args...>::type;

    // dexllm(#50): captures `state` rather than `this` — a queued task can
    // outlive the ThreadPool object (a detached worker keeps draining the queue
    // after the destructor returns), and reading should_skip_task through
    // `this` would then be a use-after-free.
    //
    // The State reference this holds is what a queued task needs to run safely;
    // it also means a pool destroyed with tasks still queued and NO worker left
    // to run them would leak State. Not reachable here (a pool always has at
    // least one worker), but it is why the queue is not simply cleared: dropping
    // a queued task would leave its `std::future` unsatisfied forever, which is
    // the very failure mode dexllm#55 exists to remove.
    auto task = std::make_shared<std::packaged_task<return_type()> >(
            [f = std::forward<F>(f), args = std::make_tuple(std::forward<Args>(args)...), state = state_]() mutable {
                if (state->should_skip_task && state->should_skip_task()) {
                    if constexpr (std::is_same_v<return_type, void>) return;
                    return return_type();
                }
                return std::apply(f, args);
            }
    );

    std::future<return_type> res = task->get_future();
    {
        std::unique_lock lock(state_->queue_mutex);

        // don't allow enqueueing after stopping the pool
        if (state_->stop)
            abort();
//            throw std::runtime_error("enqueue on stopped thread_pool");

        state_->tasks.emplace([task]() {
            (*task)();
        });
    }
    state_->condition.notify_one();
#if defined(__EMSCRIPTEN__) && !defined(__EMSCRIPTEN_PTHREADS__)
    // dexllm: no workers exist — drain the queue inline so the future resolves before
    // the caller blocks on it.
    {
        std::unique_lock lock(state_->queue_mutex);
        while (!state_->tasks.empty()) {
            auto t = std::move(state_->tasks.front());
            state_->tasks.pop();
            lock.unlock();
            t();
            lock.lock();
        }
    }
#endif
    return res;
}

// the destructor joins all threads
inline ThreadPool::~ThreadPool() {
    {
        std::unique_lock lock(state_->queue_mutex);
        state_->stop = true;
    }
    state_->condition.notify_all();
#if !(defined(__EMSCRIPTEN__) && !defined(__EMSCRIPTEN_PTHREADS__))
    // dexllm(#50): joining the thread we are running on throws
    // std::system_error "Resource deadlock avoided", which is uncaught in a
    // thread and aborts the process. Detach that one worker instead — its loop
    // reads only State, which its own reference keeps alive, and `stop` is
    // already set so it exits as soon as the queue drains.
    //
    // NOTE on that drain: on the self-destruct path this destructor no longer
    // implies "every queued task has finished". The detached worker keeps
    // running whatever is still queued AFTER the destructor returns and after
    // the owner is gone. Reachable only with a single-worker pool (any other
    // worker drains the queue before the join returns), and not reachable from
    // DexKit, whose queued dispatch lambdas each hold a reference that would
    // have kept the pool alive. Destruction from a non-worker is unchanged: it
    // still joins, so the queue is empty when it returns.
    const auto self = std::this_thread::get_id();
    std::vector<std::thread::id> joined;
    joined.reserve(workers.size());
    for (std::thread &worker: workers) {
        if (worker.get_id() == self) {
            worker.detach();
        } else {
            joined.push_back(worker.get_id());
            worker.join();
        }
    }
#else
    std::vector<std::thread::id> joined;
#endif
    // dexllm(#50): only the threads that are now DEAD. Releasing a LIVE
    // thread's matcher cache would delete the object its `thread_local` raw
    // pointer still holds (dex_item_matcher.cpp — nothing can reset another
    // thread's pointer), so the detached worker would dereference freed memory
    // on its next task. It keeps its cache instead: one leaked cache on a
    // teardown-only path, rather than a use-after-free.
    dexkit::ReleaseMatcherThreadLocalCaches(joined);
}
