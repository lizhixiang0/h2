package util.concurrent.locks;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author lizx
 * @date 2021/9/30
 * @since
 * @blog   'https://www.jianshu.com/p/4358b1466ec9
 *         ‘https://zhuanlan.zhihu.com/p/45305463
 * @descriptioon
 *
 *             synchronized的替代品
 *             1、ReentrantLock好像比synchronized关键字没好太多,最主要的就是ReentrantLock可以实现公平锁机制  (事实上公平锁效率低)
 *             2、ReentrantLock是程序员主动获取和释放锁，所以使用起来更灵活一点，比如控制 abc方法依次执行
 *
 **/
public class ReentrantLockTest {
    /**
     * 默认是非公平锁
     */
    private Lock lock = new ReentrantLock();

    public void print(String name) {
        lock.lock(); // 获取锁 ， 获取不到会阻塞
        try {

            int len = name.length();
            for (int i = 0; i < len; i++) {
                System.out.print(name.charAt(i));
            }
            System.out.println();

        } finally {
            lock.unlock(); // 释放锁
        }
    }

    public static void main(String[] args) {

    }


}
