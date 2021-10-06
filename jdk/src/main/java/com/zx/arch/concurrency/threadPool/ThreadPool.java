package com.zx.arch.concurrency.threadPool;

/**
 * 6-19
 * @author admin
 */
public interface ThreadPool<Job extends Runnable> {

    // ִ��һ��Job�����Job��Ҫʵ��Runnable
    void execute(Job job);

    // �ر��̳߳�
    void shutdown();

    // ���ӹ������߳�
    void addWorkers(int num);

    // ���ٹ������߳�
    void removeWorker(int num);

    // �õ����ڵȴ�ִ�е���������
    int getJobSize();
}
