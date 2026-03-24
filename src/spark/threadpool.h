// Copyright (c) 2022 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_SPARK_THREADPOOL_H
#define FIRO_SPARK_THREADPOOL_H

#include <algorithm>
#include <functional>
#include <memory>
#include <queue>
#include <list>
#include <vector>

#define BOOST_THREAD_PROVIDES_FUTURE

#include <boost/thread/thread.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/future.hpp>
#include <boost/chrono.hpp>

// Number of seconds before thread shuts down if idle
constexpr static int secondsBeforeThreadShutdown = 60;

// Simple thread pool for Spark wallet background tasks (moved from liblelantus with Lelantus strip).

template <typename Result>
class ParallelOpThreadPool {
private:
    std::list<boost::thread>                    threads;
    std::queue<boost::packaged_task<Result>>  task_queue;
    boost::mutex                                task_queue_mutex;
    boost::condition_variable                   task_queue_condition;

    bool                                      shutdown;
    size_t const                              number_of_threads;

    void ThreadProc() {
        for (;;) {
            boost::packaged_task<Result> job;
            {
                boost::unique_lock<boost::mutex> lock(task_queue_mutex);

                task_queue_condition.wait_for(lock, boost::chrono::seconds(secondsBeforeThreadShutdown),
                                              [this] { return !task_queue.empty() || shutdown; });
                if (task_queue.empty()) {
                    boost::thread::id currentId = boost::this_thread::get_id();
                    auto pThread = std::find_if(threads.begin(), threads.end(),
                                                [currentId](const boost::thread &t) { return t.get_id() == currentId; });
                    if (pThread != threads.end()) {
                        pThread->detach();
                        threads.erase(pThread);
                    }
                    break;
                }
                job = std::move(task_queue.front());
                task_queue.pop();
            }
            job();
        }
    }

    void StartThreads() {
        while (threads.size() < number_of_threads) {
            threads.emplace_back([this]() { ThreadProc(); });
        }
    }

public:
    ParallelOpThreadPool(std::size_t thread_number) : shutdown(false), number_of_threads(thread_number) {}

    ~ParallelOpThreadPool() {
        Shutdown();
    }

    boost::future<Result> PostTask(std::function<Result()> task) {
        boost::packaged_task<Result> packagedTask(task);
        boost::future<Result> ret = packagedTask.get_future();

        boost::mutex::scoped_lock lock(task_queue_mutex);

        if (threads.size() < number_of_threads)
            StartThreads();

        task_queue.emplace(std::move(packagedTask));
        task_queue_condition.notify_one();

        return ret;
    }

    int GetNumberOfThreads() const {
        return number_of_threads;
    }

    void Shutdown() {
        std::list<boost::thread> threadsToJoin;

        {
            boost::mutex::scoped_lock lock(task_queue_mutex);
            shutdown = true;
            task_queue_condition.notify_all();

            threadsToJoin.swap(threads);
        }

        for (boost::thread &t: threadsToJoin)
            t.join();
    }

    bool IsPoolShutdown() {
        boost::mutex::scoped_lock lock(task_queue_mutex);
        return shutdown;
    }

    std::size_t GetPendingTaskCount() {
        boost::mutex::scoped_lock lock(task_queue_mutex);
        return task_queue.size();
    }
};

class DoNotDisturb {
private:
    boost::this_thread::disable_interruption dnd;
public:
    DoNotDisturb() {}
};

#endif // FIRO_SPARK_THREADPOOL_H
