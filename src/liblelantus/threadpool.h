#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <queue>
#include <thread>
#include <vector>

template <typename T>
class ThreadSafeQueue
{
private:
    mutable CCriticalSection cs;
    std::queue<T> dataQueue;
    std::condition_variable dataCond;

    bool empty() const
    {
        LOCK(cs);
        return dataQueue.empty();
    }

public:
    ThreadSafeQueue()
    {
    }

    bool try_pop(T &value)
    {
        LOCK(cs);
        if (dataQueue.empty())
            return false;
        value = std::move(dataQueue.front());
        dataQueue.pop();
        return true;
    }

    void push(T new_value)
    {
        LOCK(cs);
        dataQueue.push(std::move(new_value));
        dataCond.notify_one();
    }
};

struct JoinThreads
{
    std::vector<std::thread>& threads;

public:
    explicit JoinThreads(std::vector<std::thread>& threads_)
        : threads(threads_)
    {
    }
    ~JoinThreads()
    {
        for (std::size_t i = 0; i < threads.size(); ++i)
        {
            if (threads[i].joinable())
                threads[i].join();
        }
    }
};

class function_wrapper {
    struct impl_base {
        virtual void call() = 0;

        virtual ~impl_base() {}
    };

    std::unique_ptr <impl_base> impl;

    template<typename F>
    struct impl_type : impl_base {
        F f;

        impl_type(F &&f_) : f(std::move(f_)) {}

        void call() { f(); }
    };
public:
    template <typename F>
    function_wrapper(F&& f) : impl(new impl_type<F>(std::move(f))) {}
    void operator()() { impl->call(); }
    function_wrapper() = default;
    function_wrapper(function_wrapper&& other) : impl(std::move(other.impl)) {}
    function_wrapper& operator=(function_wrapper&& other) {
        impl = std::move(other.impl);
        return *this;
    }
};

class ThreadPool
{
private:
    std::atomic<bool> done;
    ThreadSafeQueue<function_wrapper> poolQueue;
    std::vector<std::thread> threads;
    JoinThreads joiner;

    void WorkerThread(unsigned index)
    {
        while (!done)
        {
            function_wrapper task;
            if (poolQueue.try_pop(task))
            {
                task();
            }
            else
            {
                std::this_thread::yield();
            }
        }
    }

public:
    ThreadPool(std::size_t threadsCount = std::max(1u, std::thread::hardware_concurrency()))
        : done(false)
        , joiner(threads)
    {
        try
        {
            for (std::size_t i = 0; i < threadsCount; ++i)
            {
                threads.push_back(
                    std::thread(&ThreadPool::WorkerThread, this, i));
            }
        }
        catch (...)
        {
            done = true;
            throw;
        }
    }

    ~ThreadPool()
    {
        done = true;
    }

    template <typename FunctionType>
    std::future<typename std::result_of<FunctionType()>::type> AddTask(FunctionType f) {
        typedef typename std::result_of<FunctionType()>::type result_type;
        std::packaged_task<result_type()> task(std::move(f));
        std::future<result_type> res(task.get_future());
        poolQueue.push(std::move(task));
        return res;
    }
};

#endif