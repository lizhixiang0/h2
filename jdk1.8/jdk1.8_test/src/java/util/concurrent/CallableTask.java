package util.concurrent;


import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

/**
 * @author lizx
 * @date 2021/10/25
 * @since
 * @description  callable 和 FutureTask用法
 * @blog 'https://www.cnblogs.com/rainbow70626/p/12577918.html
 *         https://www.jianshu.com/p/9906f84b9d4d
 *
 **/
class CallableTask implements Callable<Integer> {
    @Override
    public Integer call() throws Exception {
        System.out.println("线程在进行计算");
        Thread.sleep(3000);
        int sum = 0;
        for(int i=0;i<100;i++) {
            sum += i;
        }
        return sum;
    }

    public static void main(String[] args) throws ExecutionException, InterruptedException {
        FutureTask<Integer> task = new FutureTask<>(new CallableTask());
        // 实质还是以Callable对象来创建、并启动线程
        new Thread(task , "有返回值的线程").start();
        System.out.println(task.get());
    }

}
