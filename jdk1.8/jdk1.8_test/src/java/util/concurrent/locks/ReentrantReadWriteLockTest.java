package util.concurrent.locks;

import javax.xml.crypto.Data;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * @author lizx
 * @date 2021/10/11
 * @since
 * @description    ��д�� ��
 *                 Ч���� ����߳�ͬʱ��һ����Դû���κ����⣬�������һ���߳���ȥд��Щ������Դ���Ͳ�Ӧ�����������̶߳Ը���Դ���ж���д�Ĳ���

 * @blog 'https://segmentfault.com/a/1190000015562389
 *
 **/
public class ReentrantReadWriteLockTest {
    private final Map<String, Data> m = new TreeMap<>();
    private final ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();
    // ����
    private final Lock r = rwl.readLock();
    // д��
    private final Lock w = rwl.writeLock();

    public Data get(String key) {
        r.lock();
        try {
            return m.get(key);
        } finally {
            r.unlock();
        }
    }

    public String[] allKeys() {
        r.lock();
        try {
            return (String[]) m.keySet().toArray();
        } finally {
            r.unlock();
        }
    }

    public Data put(String key, Data value) {
        w.lock();
        try {
            return m.put(key, value);
        } finally {
            w.unlock();
        }
    }

    public void clear() {
        w.lock();
        try {
            m.clear();
        } finally {
            w.unlock();
        }
    }
}