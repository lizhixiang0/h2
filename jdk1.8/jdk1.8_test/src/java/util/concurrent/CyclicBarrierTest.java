package util.concurrent;

import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;

/**
 * @author lizx
 * @date 2021/9/28
 * @since   CyclicBarrier可以理解成一个大石头，需要足够多的线程才能推开他！
 *
 *          如果有某个任务需要所有线程都执行完再去执行，那可以使用这个
 * @description   "https://segmentfault.com/a/1190000015888316
 **/
public class CyclicBarrierTest {

    /**
     * 等待线程直到满足5个线程再执行！
     * @param args
     */
    public static void main(String[] args) {

        int N = 5;  // 运动员数
        CyclicBarrier cb = new CyclicBarrier(N, () -> System.out.println("****** 所有运动员已准备完毕，发令枪：跑！******"));

        for (int i = 0; i < N; i++) {
            Thread t = new Thread(new PrepareWork(cb), "运动员[" + i + "]");
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
                System.out.println(Thread.currentThread().getName() + ": 准备完成");
                cb.await();          // 在栅栏等待
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (BrokenBarrierException e) {
                e.printStackTrace();
            }
        }
    }
}