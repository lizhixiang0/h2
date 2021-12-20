package com.wangweijun.concurrent.version1;

import java.util.List;

/**
 * @author lizx
 * @date 2021/12/10
 * @since
 **/
public interface ThreadPool {
    /**
     * 获取当前所有线程
     * @return
     */
    List<ThreadUnit> getThreads();

    /**
     * 投放任务
     * @param runnable
     */
    void putTask(Runnable runnable);

}
