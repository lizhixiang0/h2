package util.concurrent.locks;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author lizx
 * @date 2021/9/30
 * @since
 * @blog   'https://www.jianshu.com/p/4358b1466ec9
 *         ��https://zhuanlan.zhihu.com/p/45305463
 * @descriptioon
 *
 *             synchronized�����Ʒ
 *             1��ReentrantLock�����synchronized�ؼ���û��̫��,����Ҫ�ľ���ReentrantLock����ʵ�ֹ�ƽ������  (��ʵ�Ϲ�ƽ��Ч�ʵ�)
 *             2��ReentrantLock�ǳ���Ա������ȡ���ͷ���������ʹ�����������һ�㣬������� abc��������ִ��
 *
 **/
public class ReentrantLockTest {
    /**
     * Ĭ���Ƿǹ�ƽ��
     */
    private Lock lock = new ReentrantLock();

    public void print(String name) {
        lock.lock(); // ��ȡ�� �� ��ȡ����������
        try {

            int len = name.length();
            for (int i = 0; i < len; i++) {
                System.out.print(name.charAt(i));
            }
            System.out.println();

        } finally {
            lock.unlock(); // �ͷ���
        }
    }

    public static void main(String[] args) {

    }


}
