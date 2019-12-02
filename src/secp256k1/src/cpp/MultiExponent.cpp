#include "../include/MultiExponent.h"

#include "../include/secp256k1.h"
#include "../field.h"
#include "../field_impl.h"
#include "../group.h"
#include "../group_impl.h"
#include "../scalar.h"
#include "../scalar_impl.h"
#include "../ecmult.h"
#include "../ecmult_impl.h"
#include "../src/scratch_impl.h"
#include "../src/ecmult_impl.h"

#include <mutex>
#include <condition_variable>
#include <future>
#include <chrono>
#include <thread>
#include <list>
#include <queue>
#include <algorithm>

// our code currently relies on boost disable_interruption. This will go away with core upgrade
#include <boost/thread.hpp>

// Simple implementation of thread pool

namespace {

// Number of seconds before thread shuts down if idle
constexpr static int secondsBeforeThreadShutdown = 10;

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
    ParallelOpThreadPool() : shutdown(false), number_of_threads(std::thread::hardware_concurrency()) {}

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

} // namespace {


typedef struct {
    secp256k1_scalar *sc;
    secp256k1_gej *pt;
} ecmult_multi_data;

int ecmult_multi_callback(secp256k1_scalar *sc, secp256k1_gej *pt, size_t idx, void *cbdata) {
    ecmult_multi_data *data = (ecmult_multi_data*) cbdata;
    *sc = data->sc[idx];
    *pt = data->pt[idx];
    return 1;
}

namespace secp_primitives {

MultiExponent::MultiExponent(const MultiExponent& other)
        : sc_(new secp256k1_scalar[other.n_points])
        , pt_(new secp256k1_gej[other.n_points])
        , n_points(other.n_points)
{
    for(int i = 0; i < n_points; ++i)
    {
        (reinterpret_cast<secp256k1_scalar *>(sc_))[i] = (reinterpret_cast<secp256k1_scalar *>(other.sc_))[i];
        (reinterpret_cast<secp256k1_gej *>(pt_))[i] = (reinterpret_cast<secp256k1_gej *>(other.pt_))[i];
    }
}

MultiExponent::MultiExponent(const std::vector<GroupElement>& generators, const std::vector<Scalar>& powers){
    sc_ = new secp256k1_scalar[powers.size()];
    pt_ = new secp256k1_gej[generators.size()];
    n_points = generators.size();
    for(int i = 0; i < n_points; ++i)
    {
        (reinterpret_cast<secp256k1_scalar *>(sc_))[i] = *reinterpret_cast<const secp256k1_scalar *>(powers[i].get_value());
        (reinterpret_cast<secp256k1_gej *>(pt_))[i] = *reinterpret_cast<const secp256k1_gej *>(generators[i].get_value());
    }
}

MultiExponent::~MultiExponent(){
    delete []reinterpret_cast<secp256k1_scalar *>(sc_);
    delete []reinterpret_cast<secp256k1_gej *>(pt_);
}

GroupElement MultiExponent::get_multiple_single_thread(int start_point, int point_count) {
    secp256k1_gej r;

    ecmult_multi_data data;
    data.sc = reinterpret_cast<secp256k1_scalar *>(sc_) + start_point;
    data.pt = reinterpret_cast<secp256k1_gej *>(pt_) + start_point;

    secp256k1_scratch *scratch;
    if (point_count > ECMULT_PIPPENGER_THRESHOLD) {
        int bucket_window = secp256k1_pippenger_bucket_window(point_count);
        size_t scratch_size = secp256k1_pippenger_scratch_size(point_count, bucket_window);
        scratch = secp256k1_scratch_create(NULL, scratch_size + PIPPENGER_SCRATCH_OBJECTS*ALIGNMENT);
    } else {
        size_t scratch_size = secp256k1_strauss_scratch_size(point_count);
        scratch = secp256k1_scratch_create(NULL, scratch_size + STRAUSS_SCRATCH_OBJECTS*ALIGNMENT);
    }

    secp256k1_ecmult_context ctx;

    secp256k1_ecmult_multi_var(&ctx, scratch, &r, NULL, ecmult_multi_callback, &data, point_count);

    secp256k1_scratch_destroy(scratch);

    return  reinterpret_cast<secp256k1_scalar *>(&r);
}

GroupElement MultiExponent::get_multiple_single_thread() {
    return get_multiple_single_thread(0, n_points);
}

GroupElement MultiExponent::get_multiple() {
    static ParallelOpThreadPool<GroupElement> parallel_op_thread_pool;

    constexpr int min_points_per_thread = ECMULT_PIPPENGER_THRESHOLD * 3 / 2;
    int points_per_thread = std::max(n_points / parallel_op_thread_pool.GetNumberOfThreads(), min_points_per_thread);
    int n_threads = n_points / points_per_thread;

    if (n_threads <= 1)
        return get_multiple_single_thread(0, n_points);

    points_per_thread = n_points / n_threads;

    boost::this_thread::disable_interruption dnd;
    std::vector<std::shared_future<GroupElement>> parallel_tasks;

    parallel_tasks.reserve(n_threads);

    int start_point = 0;
    for (int i = 0; i < n_threads; ++i) {
        int point_count = i == n_threads-1 ? n_points - start_point : std::min(points_per_thread, n_points - start_point);
        parallel_tasks.emplace_back(parallel_op_thread_pool.PostTask([=] {
            return get_multiple_single_thread(start_point, point_count);
        }));
        start_point += point_count;
    }

    GroupElement r = parallel_tasks[0].get();
    for (int n = 1; n < n_threads; ++n)
        r += parallel_tasks[n].get();

    return r;
}

}// namespace secp_primitives
