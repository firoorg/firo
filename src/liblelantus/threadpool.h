#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <queue>
#include <thread>
#include <list>
#include <vector>

// our code currently relies on boost disable_interruption. This will go away with core upgrade
//#include <boost/thread.hpp>

// Number of seconds before thread shuts down if idle
constexpr static int secondsBeforeThreadShutdown = 60;

// Simple thread pool class for using multiple cores effeciently

template <typename Result>
class ParallelOpThreadPool {
private:
    std::list<std::thread>                    threads;
    std::queue<std::packaged_task<Result()>>  task_queue;
    std::mutex                                task_queue_mutex;
    std::condition_variable                   task_queue_condition;

    bool                                      shutdown;
    size_t const                              number_of_threads;

    void ThreadProc() {
        for (;;) {
            std::packaged_task<Result()> job;
            {
                std::unique_lock<std::mutex> lock(task_queue_mutex);

                task_queue_condition.wait_for(lock, std::chrono::seconds(secondsBeforeThreadShutdown),
                                              [this] { return !task_queue.empty() || shutdown; });
                if (task_queue.empty()) {
                    // Either timeout or shutdown. If it's a timeout we need to delete ourself from the thread list and detach the thread
                    // In case of shutdown thread list will be empty and destructor will wait for this thread completion
                    std::thread::id currentId = std::this_thread::get_id();
                    auto pThread = std::find_if(threads.begin(), threads.end(), [=](const std::thread &t) { return t.get_id() == currentId; });
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
        // should be called with mutex aquired
        // start missing threads
        while (threads.size() < number_of_threads)
            threads.emplace_back(std::bind(&ParallelOpThreadPool::ThreadProc, this));
    }

public:
    ParallelOpThreadPool(std::size_t thread_number) : number_of_threads(thread_number), shutdown(false) {}

    ~ParallelOpThreadPool() {
        std::list<std::thread> threadsToJoin;

        {
            std::unique_lock<std::mutex> lock(task_queue_mutex);
            shutdown = true;
            task_queue_condition.notify_all();

            // move the list to separate variable to wait for the shutdown process to complete
            threadsToJoin.swap(threads);
        }

        // wait for all the threads
        for (std::thread &t: threadsToJoin)
            t.join();
    }

    // Post a task to the thread pool and return a future to wait for its completion
    std::future<Result> PostTask(std::function<Result()> task) {
        std::packaged_task<Result()> packagedTask(std::move(task));
        std::future<Result> ret = packagedTask.get_future();

        std::unique_lock<std::mutex> lock(task_queue_mutex);

        // lazy start threads on first request or after shutdown
        if (threads.size() < number_of_threads)
            StartThreads();

        task_queue.emplace(std::move(packagedTask));
        task_queue_condition.notify_one();

        return std::move(ret);
    }

    int GetNumberOfThreads() const {
        return number_of_threads;
    }

};


#endif