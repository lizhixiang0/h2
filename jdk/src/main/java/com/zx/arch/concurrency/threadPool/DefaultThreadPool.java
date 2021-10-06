package com.zx.arch.concurrency.threadPool;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 *
 * @author admin
 * @param <Job>
 */
public class DefaultThreadPool<Job extends Runnable> implements ThreadPool<Job> {
    // �̳߳����������
    private static final int      MAX_WORKER_NUMBERS     = 10;
    // �̳߳�Ĭ�ϵ�����
    private static final int      DEFAULT_WORKER_NUMBERS = 5;
    // �̳߳���С������
    private static final int      MIN_WORKER_NUMBERS     = 1;
    // ����һ�������б�������������빤��
    private final LinkedList<Job> jobs                   = new LinkedList<>();
    // �������б�
    private final List<Worker>    workers                = Collections.synchronizedList(new ArrayList<Worker>());
    // �������̵߳�����
    private int                   workerNum              = DEFAULT_WORKER_NUMBERS;
    // �̱߳������
    private AtomicLong            threadNum              = new AtomicLong();

    public DefaultThreadPool() {
        initializeWokers(DEFAULT_WORKER_NUMBERS);
    }

    public DefaultThreadPool(int num) {
        workerNum = num > MAX_WORKER_NUMBERS ? MAX_WORKER_NUMBERS : num < MIN_WORKER_NUMBERS ? MIN_WORKER_NUMBERS : num;
        initializeWokers(workerNum);
    }

    @Override
    public void execute(Job job) {
        if (job != null) {
            // ���һ��������Ȼ�����֪ͨ    (��ӹ����������ͬ����������,��Ϊjobs�Ǹ�������������иı�jobs�Ķ��÷ŵ�ͬ������)
            synchronized (jobs) {
                jobs.addLast(job);
                jobs.notify();  // ����notifyʱ��ֻ��һ���ȴ��̻߳ᱻ���Ѷ��������ܱ�֤�ĸ��̻߳ᱻ���ѣ���ȡ�����̵߳�����
            }
        }
    }

    @Override
    public void shutdown() {
        for (Worker worker : workers) {
            worker.shutdown();
        }
    }

    @Override
    public void addWorkers(int num) {
        synchronized (jobs) {
            // ����������Worker�������ܳ������ֵ
            if (num + this.workerNum > MAX_WORKER_NUMBERS) {
                num = MAX_WORKER_NUMBERS - this.workerNum;
            }
            initializeWokers(num);
            this.workerNum += num;
        }
    }

    @Override
    public void removeWorker(int num) {
        synchronized (jobs) {
            if (num >= this.workerNum) {
                throw new IllegalArgumentException("beyond workNum");
            }
            // ���ո���������ֹͣWorker
            int count = 0;
            while (count < num) {
                workers.get(count).shutdown();
                count++;
            }
            this.workerNum -= count;
        }
    }

    @Override
    public int getJobSize() {
        return jobs.size();
    }

    // ��ʼ���̹߳�����
    private void initializeWokers(int num) {
        for (int i = 0; i < num; i++) {
            Worker worker = new Worker();
            workers.add(worker);
            Thread thread = new Thread(worker, "ThreadPool-Worker-" + threadNum.incrementAndGet());
            thread.start();
        }
    }

    // �����ߣ�������������
    class Worker implements Runnable {
        // �Ƿ���
        private volatile boolean running = true;

        @Override
        public void run() {
            while (running) { // ���ѭ����֤�߳�һֱ���ڲ�����
                Job job = null;
                synchronized (jobs) {
                    // ����������б��ǿյģ���ô��wait
                    while (jobs.isEmpty()) {
                        try {
                            jobs.wait();
                        } catch (InterruptedException ex) {
                            // ��֪���ⲿ��WorkerThread���жϲ���������
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }
                    // ȡ��һ��Job
                    job = jobs.removeFirst();
                }
                if (job != null) {
                    try {
                        job.run();
                    } catch (Exception ex) {
                        // ����Jobִ���е�Exception
                    }
                }
            }
        }

        public void shutdown() {
            running = false;
        }
    }
}
