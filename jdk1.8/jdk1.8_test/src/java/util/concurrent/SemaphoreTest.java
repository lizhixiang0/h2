package util.concurrent;

import java.util.concurrent.Semaphore;

/**
 * @author lizx
 * @date 2021/9/28
 * @since    控制同时访问共享资源的最大线程数量,当有线程想要访问共享资源时，需要先获取(acquire)的许可；如果许可不够了，线程需要一直等待，直到许可可用。当线程使用完共享资源后，可以归还(release)许可，以供其它需要的线程使用
 *
 * @description   "https://segmentfault.com/a/1190000015918459
 **/
public class SemaphoreTest {
    private static final int MAX_AVAILABLE = 100; // 可同时访问资源的最大线程数
    private final Semaphore available = new Semaphore(MAX_AVAILABLE, true);
    protected Object[] items = new Object[MAX_AVAILABLE];   //共享资源
    protected boolean[] used = new boolean[MAX_AVAILABLE];
    public Object getItem() throws InterruptedException {
        // 1、每个线程来获取资源之前都会使用acquire一个许可证，如果拿不到就阻塞
        available.acquire();
        return getNextAvailableItem();
    }
    public void putItem(Object x) {
        if (markAsUnused(x))
            // 2、线程归还资源后会使用release返回许可证
            available.release();
    }

    /**
     * Semaphore是在共共享资源锁上又加了一层，对于共享资源访问还是需要由锁来控制，
     * @return
     */
    private synchronized Object getNextAvailableItem() {
        for (int i = 0; i < MAX_AVAILABLE; ++i) {
            if (!used[i]) {
                used[i] = true;
                return items[i];
            }
        }
        return null;
    }
    private synchronized boolean markAsUnused(Object item) {
        for (int i = 0; i < MAX_AVAILABLE; ++i) {
            if (item == items[i]) {
                if (used[i]) {
                    used[i] = false;
                    return true;
                } else
                    return false;
            }
        }
        return false;
    }
}
