package util.concurrent;

import lombok.SneakyThrows;

import java.util.concurrent.CountDownLatch;

/**
 * @author lizx
 * @date 2021/9/28
 * @since   CountDownLatch��һ��ͬ�������࣬����Э������߳�֮���ͬ��
 *          ���԰��������һ������,���Ǹ��̵߳���await(),�Ǹ��߳̾ͱ�˨ס�����ǵ���countDown()!
 * @description   "https://www.jianshu.com/p/3766c9ca5ca4
 **/
public class CountDownLatchTest {

    private CountDownLatch begin;

    private CountDownLatch end;

    /**
     * ����10�����߳�һ��ִ���꣬��ȥִ�����߳�
     * @throws InterruptedException
     */
    public static void testCountDownLatch() throws InterruptedException {
        CountDownLatch begin = new CountDownLatch(1);  // ����Ϊ1 �������һ��countDown�ỽ�ѵȴ����е��߳�
        CountDownLatch end = new CountDownLatch(2);   // ����Ϊ2�������2��countDown�ỽ�ѵȴ����е��߳�

        for(int i=0; i< 2 ; i++){
            Thread thread = new Thread(new Player(begin,end));
            thread.start();
        }
        System.out.println("the race begin");
        begin.countDown(); // �������߳�
        end.await();// ���̷߳ŵ��ȴ�����
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
            begin.await();  // �߳�һ�����ͷŵ��ȴ�������
            System.out.println(Thread.currentThread().getName() + " arrived !");
            end.countDown(); // ����һ�����̣߳�ֱ�������̶߳�ִ��countDown�����������Σ������߳��ѹ�����
        }
    }

    public static void main(String[] args) throws InterruptedException {
        testCountDownLatch();
    }
}
