#include "Zerocoin.h"
#include "ParallelTasks.h"

#include <thread>
#include <functional>
#include <future>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <list>
#include <chrono>
#include <algorithm>

using namespace std;
namespace libzerocoin {

#ifdef ZEROCOIN_THREADING

// Number of seconds before thread shuts down if idle
constexpr static int secondsBeforeThreadShutdown = 10;

// Simple thread pool class for using multiple cores effeciently

static class ParallelOpThreadPool {
private:
    list<thread>                  threads;
    queue<packaged_task<void()>>  taskQueue;
    mutex                         taskQueueMutex;
    condition_variable            taskQueueCondition;

    bool                          shutdown;
    size_t                        numberOfThreads;

    void ThreadProc() {
        for (;;) {
            packaged_task<void()> job;
            {
                unique_lock<mutex> lock(taskQueueMutex);

                taskQueueCondition.wait_for(lock, chrono::seconds(secondsBeforeThreadShutdown),
                                            [this] { return !taskQueue.empty() || shutdown; });
                if (taskQueue.empty()) {
                    // Either timeout or shutdown. If it's a timeout we need to delete ourself from the thread list and detach the thread
                    // In case of shutdown thread list will be empty and destructor will wait for this thread completion
                    thread::id currentId = this_thread::get_id();
                    auto pThread = find_if(threads.begin(), threads.end(), [=](const thread &t) { return t.get_id() == currentId; });
                    if (pThread != threads.end()) {
                        pThread->detach();
                        threads.erase(pThread);
                    }
                    break;
                }
                job = move(taskQueue.front());
                taskQueue.pop();
            }
            job();
        }
    }

    void StartThreads() {
        // should be called with mutex aquired
        // start missing threads
        while(threads.size() < numberOfThreads)
            threads.emplace_back(bind(&ParallelOpThreadPool::ThreadProc, this));
    }

public:
    ParallelOpThreadPool() : shutdown(false), numberOfThreads(thread::hardware_concurrency()) {}

    ~ParallelOpThreadPool() {
        list<thread> threadsToJoin;

        taskQueueMutex.lock();

        shutdown = true;
        taskQueueCondition.notify_all();

        // move the list to separate variable to wait for the shutdown process to complete
        threadsToJoin.swap(threads);

        taskQueueMutex.unlock();

        // wait for all the threads
        for (thread &t: threadsToJoin)
            t.join();
    }

    // Post a task to the thread pool and return a future to wait for its completion
    future<void> PostTask(function<void()> task) {
        packaged_task<void()> packagedTask(move(task));
        future<void> ret = packagedTask.get_future();

        taskQueueMutex.lock();

        // lazy start threads on first request or after shutdown
        if (threads.size() < numberOfThreads)
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
    tasks.push_back(s_parallelOpThreadPool.PostTask(move(task)));
}

void ParallelTasks::Wait() {
    for (future<void> &f: tasks)
        f.get();
}

void ParallelTasks::Reset() {
    tasks.clear();
}

} // namespace libzerocoin
