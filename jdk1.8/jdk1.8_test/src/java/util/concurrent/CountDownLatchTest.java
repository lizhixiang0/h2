package util.concurrent;

import lombok.SneakyThrows;

import java.util.concurrent.CountDownLatch;

/**
 * @author lizx
 * @date 2021/9/28
 * @since   CountDownLatch是一个同步工具类，用来协调多个线程之间的同步
 *          可以把它想象成一个门闩,在那个线程调用await(),那个线程就被栓住！除非调用countDown()!
 * @description   "https://www.jianshu.com/p/3766c9ca5ca4
 **/
public class CountDownLatchTest {

    private CountDownLatch begin;

    private CountDownLatch end;

    /**
     * 控制10个子线程一起执行完，再去执行主线程
     * @throws InterruptedException
     */
    public static void testCountDownLatch() throws InterruptedException {
        CountDownLatch begin = new CountDownLatch(1);  // 参数为1 ，则调用一次countDown会唤醒等待队列的线程
        CountDownLatch end = new CountDownLatch(2);   // 参数为2，则调用2次countDown会唤醒等待队列的线程

        for(int i=0; i< 2 ; i++){
            Thread thread = new Thread(new Player(begin,end));
            thread.start();
        }
        System.out.println("the race begin");
        begin.countDown(); // 唤醒子线程
        end.await();// 主线程放到等待队列
        System.out.println("the race end");
    }

    static class Player implements Runnable{

        private CountDownLatch begin;

        private CountDownLatch end;

        Player(CountDownLatch begin,CountDownLatch end){
            this.begin = begin;
            this.end = end;
        }

        @SneakyThrows
        @Override
        public void run() {
            begin.await();  // 线程一进来就放到等待队列中
            System.out.println(Thread.currentThread().getName() + " arrived !");
            end.countDown(); // 唤醒一次主线程，直到所有线程都执行countDown，最起码两次，则主线程醒过来！
        }
    }

    public static void main(String[] args) throws InterruptedException {
        testCountDownLatch();
    }
}
