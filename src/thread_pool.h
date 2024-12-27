// class thread_pool, class worker queue, class task queue, class task
// thread_pool has a worker queue and a task queue
// initialize the thread pool with a number of workers

#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
using namespace std;


class Task {
    public:
        Task(){}
        virtual void run() = 0;
        virtual ~Task(){}
};

// example of a task, Task(int x) : x(x) {}, void run() { cout << x << endl; }, private x and _run();

// queue with mutex
class TaskQueue {
    public:
        TaskQueue(){
            pthread_mutex_init(&m, NULL);
            pthread_cond_init(&cv, NULL);
        }
        void push(Task* task){
            pthread_mutex_lock(&m);
            q.push(task);
            pthread_cond_signal(&cv);    
            pthread_mutex_unlock(&m);
        }
        Task* pop(){
            pthread_mutex_lock(&m);
            while(q.empty())
                pthread_cond_wait(&cv, &m);

            Task* task = q.front();
            q.pop();
            pthread_mutex_unlock(&m);
            return task;
        }
    private:
        queue<Task*> q;
        pthread_mutex_t m;
        pthread_cond_t cv;
};

class Thread{
    private:
        TaskQueue* tq;
        pthread_t thread_id;
        static void* run(void* arg){
            Thread* thread = static_cast<Thread*>(arg);
            Task* task;
            while((task = thread->tq->pop())){
                // cout << thread->thread_id << " running\n";
                task->run();
                // cout << thread->thread_id << " done\n";
                delete task;
            }
            return NULL;
        }
    public:
        // store tq reference
        Thread(TaskQueue* tq) : tq(tq){}
        void start(){
            if(pthread_create(&thread_id, NULL, run, this)){
                cerr << "pthread_create() failed\n";
            }
        }
        void join(){
            if(pthread_join(thread_id, NULL)){
                cerr << "pthread_join() failed\n";
            }
        }
};

class ThreadPool{
    private:
        TaskQueue tq;
        vector<Thread*> threads;
    public:
        ThreadPool(int n){
            for(int i = 0; i < n; i++){
                threads.push_back(new Thread(&tq));
                threads.back()->start();
            }
        }
        void add_task(Task* task){
            tq.push(task);
        }
        ~ThreadPool(){
            for(int i=0; i<threads.size(); i++){
                tq.push(nullptr);
            }
            for(auto t : threads){
                t->join();
                delete t;
            }
        }
};

#endif // THREAD_POOL_H