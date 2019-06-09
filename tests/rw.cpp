/* 
 * A template for thread based traffic generator
 *
 * Copyright (C) 2019 Saptarshi Sen
 *
 * g++ -std=c++11 -o rw rw.cpp -lpthread
 *
 */
#include <list>
#include <set>
#include <string>
#include <random>
#include <thread>
#include <mutex>
#include <random>
#include <iostream>
#include <condition_variable>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

using namespace std;

bool startIO = false;
std::mutex syncTasks_mutex;
std::condition_variable syncTasks_cv;

struct Timer {
        std::chrono::milliseconds secs_;
        std::chrono::time_point<std::chrono::steady_clock> t0_;

        void Start() {
                t0_ = std::chrono::steady_clock::now();
        }

        void Stop() {
                auto diff = std::chrono::steady_clock::now() - t0_;
                secs_ = std::chrono::duration_cast<std::chrono::milliseconds> (diff);
        }

        double Duration() {
                return secs_.count();
        }
};

// used for per file offset generation
struct Prng {
    int rmax_;
    std::mt19937 rand_;
    std::uniform_int_distribution<int> dist_;
    Prng(int rmax) :
                 rmax_(rmax),
                 rand_(std::chrono::high_resolution_clock::now().time_since_epoch().count()),
                 dist_(std::uniform_int_distribution<int>(0, rmax_))
                 {}
    int next_random_offset(void) {
            return dist_(rand_);
    }
};

struct CommonConfig {
       int mode_;
       size_t reqSize_;
       enum IOType {
            SEQUENTIAL,
            RANDOM
       } ioType_;

       CommonConfig(int mode, size_t reqSize, IOType iotype) : 
                    mode_(mode),
                    reqSize_(reqSize),
                    ioType_(iotype) {}
};

struct PerFileConfig {
        std::string file_;
        enum FileOp {
             READOP,
             WRITEOP
        } opType_;         
        size_t fileSize_;
        int thread_count_;    

        PerFileConfig(std::string file, FileOp op, size_t fSize, int thread_count) :
                   file_(file), opType_(op), fileSize_(fSize), thread_count_(thread_count)
        {}
};       

struct IOTask {
       int fd_;
       size_t reqSize_;
       size_t fileBytes_;
       size_t fileOffset_;
       float  latency_;
       short  node_affinity_;
       std::thread task_;
       std::thread::id id_;
       PerFileConfig::FileOp op_;
       CommonConfig::IOType ioType_;
       static std::set<loff_t> randomMap_;

       IOTask(std::string file, size_t fileOffset, size_t fileBytes, size_t reqSize, PerFileConfig::FileOp opType, CommonConfig::IOType ioType, int node) :
                  fileOffset_(fileOffset),
                  fileBytes_(fileBytes),
                  reqSize_(reqSize),
                  op_(opType),
                  ioType_(ioType),
                  latency_(0),
                  node_affinity_(node) {

                  fd_ = open(file.c_str(), (opType == PerFileConfig::FileOp::READOP) ? O_RDONLY : O_RDWR | O_CREAT, 0777);
                  if (fd_ < 0) {
                        std::cerr <<  "file " << file << ":" << fd_ << std::endl;
                        throw std::runtime_error("failed to open file");    
                  }
       }

       ~IOTask() {
                  assert(fd_);
                  close(fd_);
       }

       static void TaskFunc(struct IOTask *task) {
                int ret;
                Timer tp;
                void *cpubuf = NULL;
                double accum_duration = 0;
                size_t fileops = task->fileBytes_ / task->reqSize_;
                Prng prng(fileops);

                task->id_ = std::this_thread::get_id();

                assert(posix_memalign(&cpubuf, 4096, task->reqSize_) == 0);

                memset(cpubuf, 'A',  task->reqSize_);

                { 
                        std::unique_lock<std::mutex> lock(syncTasks_mutex);

                        std::cout << "Started" << std::endl;
                        std::cout << startIO << std::endl;

                        syncTasks_cv.wait(lock, [] { return startIO;});

                        //lock.unlock();
                }

                for (size_t i = 0; i < fileops; i++) {
                        loff_t j;
        
                        if (task->ioType_ == CommonConfig::IOType::RANDOM)                
                                j =  prng.next_random_offset();
                        else
                                j = i;

                        //randomMap_.insert(j);

                        tp.Start();

		        if (task->op_ == PerFileConfig::FileOp::READOP)
			        ret = pread(task->fd_, cpubuf, task->reqSize_, task->fileOffset_ + j * task->reqSize_);
		        else
			        ret = pwrite(task->fd_, cpubuf, task->reqSize_, task->fileOffset_ + j * task->reqSize_);

                        tp.Stop();

                        accum_duration += tp.Duration();

                        assert (ret >= 0);
                }

                task->latency_ = accum_duration / fileops;
       }

       static void VerifyFunc(struct IOTask *task) {
                int ret;
                Timer tp;
                void *cpubuf = NULL, *patbuf = NULL;

                task->id_ = std::this_thread::get_id();

                assert(posix_memalign(&cpubuf, 4096, task->reqSize_) == 0);
                assert(posix_memalign(&patbuf, 4096, task->reqSize_) == 0);

                memset(cpubuf, 0,  task->reqSize_);
                { 
                        std::unique_lock<std::mutex> lock(syncTasks_mutex);

                        syncTasks_cv.wait(lock, [] { return startIO;});

                        lock.unlock();
                }

                for (auto j : randomMap_) {
                        tp.Start();
		        ret = pread(task->fd_, cpubuf, task->reqSize_, task->fileOffset_ + j * task->reqSize_);
                        tp.Stop();
                        assert (ret >= 0);
                        assert(memcmp(cpubuf, patbuf, task->reqSize_) == 0);
                }
        }

       void Start() {
               task_ = std::thread(TaskFunc, this); 
       }

       void StartVerify() {
               task_ = std::thread(VerifyFunc, this); 
       }

       void Stop() {
               task_.join();
       }
};

struct TaskManager {
        struct CommonConfig g_cfg_;

        std::list<IOTask*> taskList_;
 
        void CreateTasks(PerFileConfig cfg) {
                size_t rangeSize = cfg.fileSize_ / cfg.thread_count_;
		for (int i = 0; i < cfg.thread_count_; i++) {
                        auto task = new IOTask(cfg.file_, i * rangeSize, rangeSize, g_cfg_.reqSize_, cfg.opType_, g_cfg_.ioType_, 0);
                        taskList_.push_back(task);
                        task->Start();
                        std::cout << "Created task" << std::endl;
                }
        }

        void CreateVerifyTask(PerFileConfig cfg) {
                auto task = new IOTask(cfg.file_, 0, 0, g_cfg_.reqSize_, cfg.opType_, g_cfg_.ioType_, 0);
                taskList_.push_back(task);
                task->StartVerify();
        }

        void LaunchTasks() {
                {
                        std::lock_guard<std::mutex> lock(syncTasks_mutex);
                        startIO = true;
                }
                syncTasks_cv.notify_all();
                std::cout << "Launched tasks" << std::endl;
        }

        void StopTasks() {
                startIO = false;
                for (auto worker : taskList_) {
			worker->Stop();  
                        std::cout << " Thread :" << worker->id_
                                  << " reqSize :" << worker->reqSize_
                                  << " fileBytes :" << worker->fileBytes_
                                  << " fileOffset :" << worker->fileOffset_
                                  << " Latency :" << worker->latency_ << " ms"
                                  << std::endl;
                        delete worker;
                }         
                taskList_.clear();
        }

        void MonitorTasks() {

        }

        TaskManager(struct CommonConfig gcfg) : g_cfg_(gcfg) {}
};

//Template Configs

const struct CommonConfig randIO_cfg = {
        .mode_    = 0,
        .reqSize_ = 4 * 1024,
        .ioType_  = CommonConfig::RANDOM,
};

const struct PerFileConfig file_cfg = {
        .file_          = std::string("/mnt/sample"),
        .opType_        = PerFileConfig::FileOp::WRITEOP,
        .fileSize_      = (1 << 20UL),
        .thread_count_  = 1,
};

std::set<loff_t> IOTask::randomMap_;

int main(void) {
         struct TaskManager task_mgr(randIO_cfg);

         task_mgr.CreateTasks(file_cfg);

         task_mgr.LaunchTasks();

         task_mgr.StopTasks();

         //task_mgr.CreateVerifyTask(file_cfg);

         //task_mgr.LaunchTasks();

         //task_mgr.StopTasks();

         return 0;
}
