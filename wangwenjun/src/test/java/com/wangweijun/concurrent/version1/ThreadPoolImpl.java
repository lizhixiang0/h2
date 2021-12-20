package com.wangweijun.concurrent.version1;

import lombok.SneakyThrows;

import java.util.LinkedList;
import java.util.List;

/**
 * @author lizx
 * @date 2021/12/10
 * @since
 **/
public class ThreadPoolImpl implements ThreadPool{

    private final static Long DEFAULT_MAX_THREAD_COUNT = 10L;

    private final static Long DEFAULT_TASKS_COUNT = 50L;

    private final static Long DEFAULT_FREE_TIME = 5000L;

    private Long coreThread;

    private  Long maxThread ;

    private  Long maxTask ;
    /**
     *
     */
    private  Long freeTime ;

    /**
     * ¥Ê∑≈»ŒŒÒ
     */
    private LinkedList<Runnable> tasks;


    private ThreadPoolImpl(Long coreThread, Long maxThread, Long maxTask, Long freeTime){
        this.coreThread =  10L;
        this.maxTask =  maxTask ==null ? DEFAULT_TASKS_COUNT :  maxTask;
        this.freeTime =  freeTime==null ? DEFAULT_FREE_TIME :  freeTime;
        this.maxThread =  maxThread==null ? DEFAULT_MAX_THREAD_COUNT :  maxTask;
    }

    public static ThreadPoolImpl newInstance() {
        return  new ThreadPoolImpl(null,null,null,null);
    }


    @Override
    public List<ThreadUnit> getThreads() {
        return null;
    }

    @Override
    public void putTask(Runnable runnable) {
        synchronized (tasks){
            if (tasks.size()<maxTask){
                tasks.addLast(runnable);
                tasks.notify();
            }else {
                new RejectionPolicy.ThrowExceptionPolicy().handle();
            }

        }
    }

    public void exec(){
        tasks = new LinkedList<>();
        for (int i=0;i<coreThread;i++){
            new ExecutableThread(tasks).start();
        }
    }


    private class ExecutableThread extends Thread{

        private LinkedList<Runnable> tasks;

        public ExecutableThread(LinkedList<Runnable> tasks){
            this.tasks = tasks;
        }

        public Runnable take() throws InterruptedException {
            synchronized (tasks){
                while (tasks.size()==0){
                    tasks.wait();
                }
                Runnable first = tasks.removeFirst();
                return first;
            }
        }

        @SneakyThrows
        @Override
        public void run() {
            while (true){
                Runnable take = take();
                take.run();
            }
        }
    }
}
