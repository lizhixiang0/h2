package util.concurrent;

import java.util.concurrent.Semaphore;

/**
 * @author lizx
 * @date 2021/9/28
 * @since    ����ͬʱ���ʹ�����Դ������߳�����,�����߳���Ҫ���ʹ�����Դʱ����Ҫ�Ȼ�ȡ(acquire)����ɣ������ɲ����ˣ��߳���Ҫһֱ�ȴ���ֱ����ɿ��á����߳�ʹ���깲����Դ�󣬿��Թ黹(release)��ɣ��Թ�������Ҫ���߳�ʹ��
 *
 * @description   "https://segmentfault.com/a/1190000015918459
 **/
public class SemaphoreTest {
    private static final int MAX_AVAILABLE = 100; // ��ͬʱ������Դ������߳���
    private final Semaphore available = new Semaphore(MAX_AVAILABLE, true);
    protected Object[] items = new Object[MAX_AVAILABLE];   //������Դ
    protected boolean[] used = new boolean[MAX_AVAILABLE];
    public Object getItem() throws InterruptedException {
        // 1��ÿ���߳�����ȡ��Դ֮ǰ����ʹ��acquireһ�����֤������ò���������
        available.acquire();
        return getNextAvailableItem();
    }
    public void putItem(Object x) {
        if (markAsUnused(x))
            // 2���̹߳黹��Դ���ʹ��release�������֤
            available.release();
    }

    /**
     * Semaphore���ڹ�������Դ�����ּ���һ�㣬���ڹ�����Դ���ʻ�����Ҫ���������ƣ�
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
