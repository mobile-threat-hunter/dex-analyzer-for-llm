// thread_pool_selfdestruct_test — dexllm(#50) regression.
//
// NOT a DAD parity suite. It guards one property of the vendored
// `ThreadPool` (third_party/thread_helper/ThreadPool.h):
//
//     the LAST reference to a pool may be dropped on one of its own workers,
//     and destroying it there must not abort the process.
//
// In production the edge is one hop longer: `QueryScheduler::EnqueueDispatchTasks`
// captures a `shared_ptr` to the scheduler into a lambda that runs ON the pool,
// and the scheduler owns the pool. So when `DexKit` drops its references while a
// dispatched lambda is still alive, the last scheduler reference is the one
// inside that lambda — destroying it on the worker destroys the pool there, and
// `~ThreadPool` then joined the thread it was executing on:
// `std::system_error` "Resource deadlock avoided", uncaught in a thread,
// `std::terminate`. Case 1 below is that ownership edge with the scheduler hop
// removed; case 2 restores the hop so the guard covers the reported shape too.
//
// This test ABORTS (does not merely fail) against the pre-fix ThreadPool — an
// abort is the defect. It is therefore run as its own ctest process.
//
// The observation point matters, and the first version of this file got it
// wrong: a flag set by the TASK (or by the intermediate owner's destructor)
// fires BEFORE the pool is destroyed, so the test could reach its end and exit
// while the dangerous destruction had not happened yet — case 2 then passed
// against the pre-fix header. Every case here signals from a shared_ptr DELETER,
// which runs strictly AFTER `~ThreadPool` has returned, so "the flag is set"
// means "the pool was destroyed on that thread and we survived".

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "ThreadPool.h"

// The matcher-cache registry is STUBBED here rather than linked, so a case can
// assert WHICH thread ids the destructor hands it. That is not observable with
// the real implementation, and without it the "release only the JOINED ids"
// fix — the one that stops a LIVE detached worker's cache from being deleted
// out from under its `thread_local` raw pointer — is one line from silent
// reversion (a reviewer's mutant survived 15/15 before this stub existed).
namespace dexkit {
static std::mutex g_released_mutex;
static std::vector<std::thread::id> g_released;

void RegisterMatcherThreadLocalCache(std::thread::id, void *, void (*)(void *)) {}

void ReleaseMatcherThreadLocalCaches(const std::vector<std::thread::id> &thread_ids) {
    std::lock_guard lock(g_released_mutex);
    g_released.insert(g_released.end(), thread_ids.begin(), thread_ids.end());
}

static std::vector<std::thread::id> TakeReleased() {
    std::lock_guard lock(g_released_mutex);
    auto out = g_released;
    g_released.clear();
    return out;
}
}  // namespace dexkit

static int g_fail = 0;

static void check(const char* label, bool ok) {
    if (!ok) ++g_fail;
    std::printf("%s %s\n", ok ? "[ok]  " : "[FAIL]", label);
}

// Waits for `flag`, but never forever — a deadlock is reported as a failure
// rather than hanging the suite.
static bool await(const std::atomic<bool>& flag, int timeout_ms = 10000) {
    for (int waited = 0; waited < timeout_ms; waited += 5) {
        if (flag.load()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return flag.load();
}

// A pool whose `destroyed` flag is set only once ~ThreadPool has RETURNED, and
// which records WHICH thread ran the destructor.
namespace {
struct Observed {
    std::atomic<bool> destroyed{false};
    std::thread::id destroyed_on{};
};
}

static std::shared_ptr<ThreadPool> MakeObservedPool(size_t threads, Observed* obs) {
    return {new ThreadPool(threads), [obs](ThreadPool* p) {
        obs->destroyed_on = std::this_thread::get_id();
        delete p;
        obs->destroyed.store(true);
    }};
}

// Every self-destruct case needs the LAST reference to land on a worker, and
// that is a race unless it is forced: if the task finishes before the enqueuing
// thread drops its own reference, the destruction happens on the MAIN thread and
// the case passes without exercising anything. So the task parks until the
// enqueuing thread has released, and each case then ASSERTS which thread ran the
// destructor rather than assuming.
static void ParkUntil(const std::atomic<bool>& go) {
    for (int i = 0; i < 4000 && !go.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

// 1. The task owns the pool directly. After the enqueuing thread drops its
//    reference, the lambda is the sole owner and is destroyed on a worker.
static void SelfDestructThroughTheTask() {
    Observed obs;
    std::atomic<bool> released{false};
    {
        auto pool = MakeObservedPool(4, &obs);
        pool->enqueue([pool, &released]() mutable { ParkUntil(released); });
        pool.reset();
        released.store(true);
    }
    check("task owning its own pool: destruction on the worker completes",
          await(obs.destroyed) && obs.destroyed_on != std::this_thread::get_id());
}

// 2. The reported shape: task -> Holder -> pool, i.e. the last reference to an
//    intermediate owner (QueryScheduler in production) lands on a worker, and
//    destroying THAT releases the pool there.
namespace {
struct Holder {
    std::shared_ptr<ThreadPool> pool;
};
}

static void SelfDestructThroughAnIntermediateOwner() {
    Observed obs;
    std::atomic<bool> released{false};
    {
        auto holder = std::make_shared<Holder>(Holder{MakeObservedPool(4, &obs)});
        auto* pool = holder->pool.get();
        pool->enqueue([holder, &released]() mutable { ParkUntil(released); });
        holder.reset();
        released.store(true);
    }
    check("scheduler-shaped owner released on a worker: destruction completes",
          await(obs.destroyed) && obs.destroyed_on != std::this_thread::get_id());
}

// 3. The destruction happens with the queue still NON-empty and only ONE
//    worker, so the detached worker keeps running tasks after ~ThreadPool has
//    returned and the object is gone. This is what exercises the OTHER half of
//    the fix — the shared State — because a worker that still reached through
//    `this` would now be touching freed memory. Without this case, reverting
//    the worker's capture to `this` passes the whole file in a normal build
//    (it is only caught under ASan).
static void QueuedWorkOutlivesTheDestroyedPool() {
    std::atomic<int> after{0};
    Observed obs;
    std::atomic<bool> release{false};
    constexpr int kTrailing = 16;
    {
        auto pool = MakeObservedPool(1, &obs);
        // The first task owns the pool and blocks until the trailing tasks are
        // queued behind it, so the queue is guaranteed non-empty at destruction.
        pool->enqueue([pool, &release]() mutable {
            for (int i = 0; i < 2000 && !release.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
        });
        for (int i = 0; i < kTrailing; ++i)
            pool->enqueue([&after]() { after.fetch_add(1); });
        pool.reset();
        release.store(true);
    }
    const bool done = await(obs.destroyed);
    // Every trailing task must still run, on a pool object that no longer
    // exists, without crashing.
    for (int i = 0; i < 400 && after.load() < kTrailing; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    check("queued work survives the pool being destroyed on its own worker",
          done && obs.destroyed_on != std::this_thread::get_id()
              && after.load() == kTrailing);
}

// 4. The fix must not weaken the ordinary contract: when the pool is destroyed
//    from a NON-worker, every queued task has completed by the time the
//    destructor returns. (The self-destruct path detaches one worker; this pins
//    that the other path still joins.)
static void OrdinaryDestructionStillJoins() {
    std::atomic<int> done{0};
    constexpr int kTasks = 64;
    {
        ThreadPool pool(4);
        for (int i = 0; i < kTasks; ++i) {
            pool.enqueue([&done]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                done.fetch_add(1);
            });
        }
    }  // ~ThreadPool on the main thread must join, i.e. drain every task
    check("destruction from a non-worker still joins every task",
          done.load() == kTasks);
}

// 5. A LIVE thread's matcher cache must never be released. The registry deletes
//    the cache object, and `dex_item_matcher.cpp` holds it in a `thread_local`
//    RAW pointer that no other thread can reset — so releasing the detached
//    worker's id would leave it dereferencing freed memory on its next task.
//    Destroying from a NON-worker must still release every worker (they are all
//    dead by then), which is what keeps this from being satisfied by releasing
//    nothing at all.
static void OnlyDeadThreadsHaveTheirCachesReleased() {
    (void) dexkit::TakeReleased();
    Observed obs;
    std::atomic<bool> released_go{false};
    {
        auto pool = MakeObservedPool(4, &obs);
        pool->enqueue([pool, &released_go]() mutable { ParkUntil(released_go); });
        pool.reset();
        released_go.store(true);
    }
    const bool done = await(obs.destroyed);
    auto released = dexkit::TakeReleased();
    const bool on_worker = obs.destroyed_on != std::this_thread::get_id();
    const bool self_released =
            std::find(released.begin(), released.end(), obs.destroyed_on) != released.end();
    check("the detached worker's cache is NOT released while it is alive",
          done && on_worker && !self_released);
    // The 3 workers that were joined are dead, so their caches must be freed.
    check("the joined workers' caches ARE released", released.size() == 3);

    // The ordinary path releases every worker.
    {
        ThreadPool pool(4);
        pool.enqueue([]() {});
    }
    check("destruction from a non-worker releases every worker's cache",
          dexkit::TakeReleased().size() == 4);
}

// 6. dexllm(#55): the CONSTRUCTOR must be exception-safe. `std::thread`'s ctor
//    throws when the process is out of threads (EAGAIN under RLIMIT_NPROC or a
//    container pids limit); unwinding out of a partially built pool destroys a
//    still-JOINABLE `std::thread`, which is `std::terminate()` — the process
//    dies before any caller's catch runs, silently voiding the recovery path
//    InitDexCache builds on that scope being catchable.
//
//    Failing the FIRST thread was survivable even before the fix (nothing was
//    built yet), so the case has to fail a LATER one — which is why the limit is
//    CALIBRATED here rather than guessed from a process count: RLIMIT_NPROC
//    counts threads for the whole uid, so an estimate misses the one-value
//    window and the test then passes against the defect (it did).
#if defined(__linux__)
#include <sys/resource.h>

static bool CanSpawnUnderLimit(rlim_t soft, rlim_t hard) {
    struct rlimit rl {soft, hard};
    if (setrlimit(RLIMIT_NPROC, &rl) != 0) return false;
    try {
        std::thread t([] {});
        t.join();
        return true;
    } catch (...) {
        return false;
    }
}

static void ConstructorIsExceptionSafeWhenOutOfThreads() {
    struct rlimit orig {};
    if (getrlimit(RLIMIT_NPROC, &orig) != 0) {
        std::printf("[skip] RLIMIT_NPROC unavailable\n");
        return;
    }
    // Smallest limit that still allows exactly one more thread. The ceiling
    // must not exceed the HARD limit or setrlimit refuses it outright, which
    // would make the probe report "cannot spawn" and skip the whole case.
    rlim_t ceiling = 1u << 20;
    if (orig.rlim_max != RLIM_INFINITY && orig.rlim_max < ceiling) ceiling = orig.rlim_max;
    rlim_t lo = 0, hi = ceiling;
    if (!CanSpawnUnderLimit(hi, orig.rlim_max)) {
        setrlimit(RLIMIT_NPROC, &orig);
        std::printf("[skip] cannot spawn even at the probe ceiling\n");
        return;
    }
    while (lo + 1 < hi) {
        rlim_t mid = lo + (hi - lo) / 2;
        if (CanSpawnUnderLimit(mid, orig.rlim_max)) hi = mid; else lo = mid;
    }
    // At `hi` exactly one thread can be created, so a 4-thread pool fails on
    // its SECOND — the shape that used to abort.
    struct rlimit tight {hi, orig.rlim_max};
    bool threw = false;
    if (setrlimit(RLIMIT_NPROC, &tight) == 0) {
        try {
            ThreadPool pool(4);
            pool.enqueue([]() {});
        } catch (...) {
            threw = true;
        }
    }
    setrlimit(RLIMIT_NPROC, &orig);
    (void) dexkit::TakeReleased();
    // Reaching here at all is the assertion: the defect TERMINATES the process.
    check("the constructor reports being out of threads instead of terminating",
          threw);
}
#else
static void ConstructorIsExceptionSafeWhenOutOfThreads() {
    std::printf("[skip] RLIMIT_NPROC behaviour is Linux-specific\n");
}
#endif

// 7. A task enqueued from INSIDE a task still runs, and the pool is still
//    destructible afterwards — the queue is not closed by the nested submit.
static void NestedEnqueueStillRuns() {
    std::atomic<bool> inner{false};
    {
        ThreadPool pool(4);
        pool.enqueue([&pool, &inner]() {
            pool.enqueue([&inner]() { inner.store(true); });
        });
        // Give the outer task time to submit before the destructor sets `stop`;
        // enqueueing after stop is an abort() by upstream's own design, which
        // this test deliberately does not exercise.
        (void) await(inner);
    }
    check("a task enqueued from inside a task still runs", inner.load());
}

int main() {
    SelfDestructThroughTheTask();
    SelfDestructThroughAnIntermediateOwner();
    QueuedWorkOutlivesTheDestroyedPool();
    OrdinaryDestructionStillJoins();
    OnlyDeadThreadsHaveTheirCachesReleased();
    ConstructorIsExceptionSafeWhenOutOfThreads();
    NestedEnqueueStillRuns();

    std::printf("\n%s: thread_pool_selfdestruct_test (%d failure(s))\n",
                g_fail == 0 ? "PASS" : "FAIL", g_fail);
    return g_fail == 0 ? 0 : 1;
}
