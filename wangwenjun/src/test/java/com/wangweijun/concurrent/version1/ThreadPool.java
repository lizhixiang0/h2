package com.wangweijun.concurrent.version1;

import java.util.List;

/**
 * @author lizx
 * @date 2021/12/10
 * @since
 **/
public interface ThreadPool {
    /**
     * ��ȡ��ǰ�����߳�
     * @return
     */
    List<ThreadUnit> getThreads();

    /**
     * Ͷ������
     * @param runnable
     */
    void putTask(Runnable runnable);

}
