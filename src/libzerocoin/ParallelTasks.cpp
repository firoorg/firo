#include "Zerocoin.h"
#include "ParallelTasks.h"

#include <thread>
#include <functional>
#include <future>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>

using namespace std;
namespace libzerocoin {

#ifdef ZEROCOIN_THREADING

// Simple thread pool class for using multiple cores effeciently

static class ParallelOpThreadPool {
private:
    vector<thread>                threads;
    queue<packaged_task<void()>>  taskQueue;
    mutex                         taskQueueMutex;
    condition_variable            taskQueueCondition;

    bool                          shutdown;

    void StartThreads() {
        int nHardwareThreads = thread::hardware_concurrency();

        auto threadProc = [this]() {
            for (;;) {
                packaged_task<void()> job;
                {
                    unique_lock<mutex> lock(taskQueueMutex);

                    taskQueueCondition.wait(lock, [this]{return !taskQueue.empty() || shutdown; });
                    if (taskQueue.empty())
                        break;
                    job = move(taskQueue.front());
                    taskQueue.pop();
                }
                job();
            }
        };

        for (int i=0; i<nHardwareThreads; i++)
            threads.emplace_back(threadProc);
    }

public:
    ParallelOpThreadPool() : shutdown(false) {}

    ~ParallelOpThreadPool() {
        taskQueueMutex.lock();
        shutdown = true;
        taskQueueCondition.notify_all();
        taskQueueMutex.unlock();

        for (thread &t: threads)
            t.join();
    }

    // Post a task to the thread pool and return a future to wait for its completion
    future<void> PostTask(function<void()> task) {
        packaged_task<void()> packagedTask(move(task));
        future<void> ret = packagedTask.get_future();

        taskQueueMutex.lock();

        // lazy start threads on first request
        if (threads.size() == 0)
            StartThreads();

        taskQueue.emplace(move(packagedTask));
        taskQueueCondition.notify_one();

        taskQueueMutex.unlock();

        return ret;
    }

} s_parallelOpThreadPool;

#else

static class ParallelOpThreadPool {
public:
    future<void> PostTask(function<void()> task) {
        task();
        promise<void> promise;
        promise.set_value();
        return promise.get_future();
    }
} s_parallelOpThreadPool;

#endif

// High level API to create number of parallel tasks and wait for completion

ParallelTasks::ParallelTasks(int n) {
    tasks.reserve(n);
}

void ParallelTasks::Add(function<void()> task) {
    tasks.push_back(s_parallelOpThreadPool.PostTask(task));
}

void ParallelTasks::Wait() {
    for (future<void> &f: tasks)
        f.get();
}

void ParallelTasks::Reset() {
    tasks.clear();
}

} // namespace libzerocoin
