/**
* @file       ParallelTasks.cpp
*
* @brief      ParallelTasks class for the Zerocoin library.
*
* @author     Peter Shugalev
* @date       Nov 2017
*
* @copyright  Copyright 2017 Peter Shugalev
* @license    This project is released under the MIT license.
**/

#include "Zerocoin.h"
#include "ParallelTasks.h"

#define BOOST_THREAD_PROVIDES_FUTURE

#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/future.hpp>
#include <boost/chrono.hpp>

#include <queue>
#include <vector>
#include <list>
#include <algorithm>
#include <functional>

namespace libzerocoin {

#ifdef ZEROCOIN_THREADING

// Number of seconds before thread shuts down if idle
constexpr static int secondsBeforeThreadShutdown = 10;

// Simple thread pool class for using multiple cores effeciently

static class ParallelOpThreadPool {
private:
    std::list<boost::thread>                  threads;
    std::queue<boost::packaged_task<void>>    taskQueue;
    boost::mutex                              taskQueueMutex;
    boost::condition_variable                 taskQueueCondition;

    bool                                      shutdown;
    size_t                                    numberOfThreads;

    void ThreadProc() {
        for (;;) {
            boost::packaged_task<void> job;
            {
                boost::unique_lock<boost::mutex> lock(taskQueueMutex);

                taskQueueCondition.wait_for(lock, boost::chrono::seconds(secondsBeforeThreadShutdown),
                                            [this] { return !taskQueue.empty() || shutdown; });
                if (taskQueue.empty()) {
                    // Either timeout or shutdown. If it's a timeout we need to delete ourself from the thread list and detach the thread
                    // In case of shutdown thread list will be empty and destructor will wait for this thread completion
                    boost::thread::id currentId = boost::this_thread::get_id();
                    auto pThread = find_if(threads.begin(), threads.end(), [=](const boost::thread &t) { return t.get_id() == currentId; });
                    if (pThread != threads.end()) {
                        pThread->detach();
                        threads.erase(pThread);
                    }
                    break;
                }
                job = std::move(taskQueue.front());
                taskQueue.pop();
            }
            job();
        }
    }

    void StartThreads() {
        // should be called with mutex aquired
        // start missing threads
        while(threads.size() < numberOfThreads)
            threads.emplace_back(std::bind(&ParallelOpThreadPool::ThreadProc, this));
    }

public:
    ParallelOpThreadPool() : shutdown(false), numberOfThreads(boost::thread::hardware_concurrency()) {}

    ~ParallelOpThreadPool() {
        std::list<boost::thread> threadsToJoin;

        taskQueueMutex.lock();

        shutdown = true;
        taskQueueCondition.notify_all();

        // move the list to separate variable to wait for the shutdown process to complete
        threadsToJoin.swap(threads);

        taskQueueMutex.unlock();

        // wait for all the threads
        for (boost::thread &t: threadsToJoin)
            t.join();
    }

    // Post a task to the thread pool and return a future to wait for its completion
    boost::future<void> PostTask(function<void()> task) {
        boost::packaged_task<void> packagedTask(std::move(task));
        boost::future<void> ret = packagedTask.get_future();

        taskQueueMutex.lock();

        // lazy start threads on first request or after shutdown
        if (threads.size() < numberOfThreads)
            StartThreads();

        taskQueue.emplace(std::move(packagedTask));
        taskQueueCondition.notify_one();

        taskQueueMutex.unlock();

        return ret;
    }

} s_parallelOpThreadPool;

#else

static class ParallelOpThreadPool {
public:
    boost::future<void> PostTask(function<void()> task) {
        task();
        boost::promise<void> promise;
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
    tasks.push_back(s_parallelOpThreadPool.PostTask(std::move(task)));
}

void ParallelTasks::Wait() {
    for (boost::future<void> &f: tasks)
        f.get();
}

void ParallelTasks::Reset() {
    tasks.clear();
}

} // namespace libzerocoin
