package util.concurrent;

import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;

/**
 * @author lizx
 * @date 2021/9/28
 * @since   CyclicBarrier��������һ����ʯͷ����Ҫ�㹻����̲߳����ƿ�����
 *
 *          �����ĳ��������Ҫ�����̶߳�ִ������ȥִ�У��ǿ���ʹ�����
 * @description   "https://segmentfault.com/a/1190000015888316
 **/
public class CyclicBarrierTest {

    /**
     * �ȴ��߳�ֱ������5���߳���ִ�У�
     * @param args
     */
    public static void main(String[] args) {

        int N = 5;  // �˶�Ա��
        CyclicBarrier cb = new CyclicBarrier(N, () -> System.out.println("****** �����˶�Ա��׼����ϣ�����ǹ���ܣ�******"));

        for (int i = 0; i < N; i++) {
            Thread t = new Thread(new PrepareWork(cb), "�˶�Ա[" + i + "]");
            t.start();
        }

    }


    private static class PrepareWork implements Runnable {
        private CyclicBarrier cb;

        PrepareWork(CyclicBarrier cb) {
            this.cb = cb;
        }

        @Override
        public void run() {

            try {
                Thread.sleep(500);
                System.out.println(Thread.currentThread().getName() + ": ׼�����");
                cb.await();          // ��դ���ȴ�
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (BrokenBarrierException e) {
                e.printStackTrace();
            }
        }
    }
}