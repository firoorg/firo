#ifndef PARALLELTASKS_H
#define PARALLELTASKS_H

#include <vector>
#include <functional>

#define BOOST_THREAD_PROVIDES_FUTURE


#include <boost/thread/future.hpp>

namespace libzerocoin {

class ParallelTasks {
private:
    vector<boost::future<void>> tasks;

public:
    ParallelTasks(int n=0);

    // add new task
    void Add(std::function<void()> task);

    // wait for everything added so far
    void Wait();

    // clear all the tasks from the waiting list
    void Reset();
};

}

#endif // PARALLELTASKS_H
