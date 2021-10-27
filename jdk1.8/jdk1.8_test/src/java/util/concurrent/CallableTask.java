package util.concurrent;


import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

/**
 * @author lizx
 * @date 2021/10/25
 * @since
 * @description  callable �� FutureTask�÷�
 * @blog 'https://www.cnblogs.com/rainbow70626/p/12577918.html
 *         https://www.jianshu.com/p/9906f84b9d4d
 *
 **/
class CallableTask implements Callable<Integer> {
    @Override
    public Integer call() throws Exception {
        System.out.println("�߳��ڽ��м���");
        Thread.sleep(3000);
        int sum = 0;
        for(int i=0;i<100;i++) {
            sum += i;
        }
        return sum;
    }

    public static void main(String[] args) throws ExecutionException, InterruptedException {
        FutureTask<Integer> task = new FutureTask<>(new CallableTask());
        // ʵ�ʻ�����Callable�������������������߳�
        new Thread(task , "�з���ֵ���߳�").start();
        System.out.println(task.get());
    }

}
