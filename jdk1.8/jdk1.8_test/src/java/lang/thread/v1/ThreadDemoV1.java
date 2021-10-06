package lang.thread.v1;

import lombok.SneakyThrows;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;
import java.sql.Time;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class ThreadDemoV1 {

    private static volatile boolean notStart = true;

    private static volatile boolean notEnd = true;

    private static Object lock = new Object();


    public void mxBean(){
        // 获得java线程管理MxBean
        ThreadMXBean threadMXBean = ManagementFactory.getThreadMXBean();
        // 不需要获得monitor和synchronizer信息
        ThreadInfo[] threadInfos = threadMXBean.dumpAllThreads(false, false);
        for (ThreadInfo threadInfo: threadInfos){
            System.out.println("["+threadInfo.getThreadId()+"]"+ threadInfo.getThreadName());
        }

        /*
            [6]Monitor Ctrl-Break           idea中特有的线程，https://www.jianshu.com/p/2cfd551055d7
            [5]Attach Listener              负责接收和反馈外部的jvm命令
            [4]Signal Dispatcher            发送信号给jvm的线程
            [3]Finalizer                    主要用于在垃圾收集前，调用对象的finalize()方法
            [2]Reference Handler            用于处理引用对象本身（软引用、弱引用、虚引用）的垃圾回收问题
            [1]main                         用户线程入口
        */
    }

    public static void testPriority() throws InterruptedException {
        List<Job> jobs = new ArrayList<>();
        for (int i=0;i<10;i++){
            int priority = i<5?Thread.MIN_PRIORITY:Thread.MAX_PRIORITY;
            Job job = new Job(priority);
            jobs.add(job);
            Thread thread  = new Thread(job,"Thread:" + i);
            thread.setPriority(priority);
            thread.start();
        }
        notStart = false;
        TimeUnit.SECONDS.sleep(5);
        notEnd = false;

        for (Job job : jobs){
            System.out.println("Job priority : " + job.priority + " , count： " + job.jobCount);
        }
    }

    static class Job implements Runnable {

        private  int priority;

        private  long jobCount;

        public Job(int priority){
            this.priority = priority;
        }

        @Override
        public void run() {
            while (notStart){
                Thread.yield(); // 进入就绪队列,等待cpu调度
            }
            while (notEnd){
                Thread.yield(); // 进入就绪队列
                jobCount++;
            }
        }
    }

    /**
     * 当一个java虚拟机中不存在非Daemon线程的时候，JAVA虚拟机将会退出！
     * java虚拟机退出时，Daemon线程中的finally块不一定执行,所以不能使用daemon线程来关闭资源 (一旦所有User Thread离开了，虚拟机也就退出运行了,此时守护线程不一定来得及执行)
     * https://blog.csdn.net/shimiso/article/details/8964414
     */
    public static void testDaemonThread(){
        Thread thread = new Thread(new DaemonThread());
        thread.setDaemon(true); // setDeamon(true)的唯一意义就是告诉JVM不需要等待它退出,让JVM喜欢什么退出就退出吧,不用管它
        thread.start();
    }

    static class DaemonThread implements Runnable {

        @Override
        public void run() {
            try {
                TimeUnit.SECONDS.sleep(5);
            } catch (InterruptedException e) {
                System.out.println(1);
//                e.printStackTrace();
            } finally {
                System.out.println(2);
            }
//            while (true){
//
//            }

        }

    }

    /**
     * 在线程处于“waiting, sleeping”甚至是正在运行的过程中，如果被中断了，就可以抛出InterruptedException异常,同时，异常抛出后，当前线程的中断状态也会被清除。
     * 中断并不会直接将一个线程停掉，在被中断的线程的角度看来，仅仅是自己的中断标志位被设为true了，或者自己所执行的代码中抛出了一个InterruptedException异常，仅此而已。
     * @throws InterruptedException
     */
    public static  void testInterrupt() throws InterruptedException {
        Thread thread = new Thread(new DaemonThread(),"interrupt");
        thread.start();
        TimeUnit.SECONDS.sleep(4);


        thread.interrupt(); // 发出中断信号,线程此时处于sleep状态，所以会抛出异常，并且清除中断标识
        TimeUnit.SECONDS.sleep(5);

        System.out.println(thread.isInterrupted());

    }

    static class WaitThread implements Runnable {

        @Override
        public void run() {
            synchronized (lock) {  // 锁对象
                while (notStart){ // 这里必须使用while,线程被唤醒后，还要继续检查状态是否符合要求!
                    try{
                        System.out.println("不满足条件");
                        lock.wait(); // 把当前线程加到锁对象的等待队列中去
                        System.out.println("继续");  // 线程被唤醒后接着执行
                    }catch (InterruptedException e){
                    }
                }
                System.out.println("满足条件,开始执行业务逻辑");
            }
        }
    }

    static class NotifyThread implements Runnable {

        @SneakyThrows
        @Override
        public void run() {
            synchronized (lock) {

                lock.notifyAll();
                TimeUnit.SECONDS.sleep(5);
                notStart = false;
            }
        }
    }


    public static void testWait() throws InterruptedException {
        Thread wait = new Thread(new WaitThread(),"wait");
        Thread notify = new Thread(new NotifyThread(),"notify");
        wait.start();
        TimeUnit.SECONDS.sleep(2);
        notify.start();
    }

    static class WaitTimeThread implements Runnable {
        /**
         * 超过5s没有执行就抛异常
         */
        private static long  time = 5000;

        @SneakyThrows
        @Override
        public void run() {
            synchronized (lock) {
                long future  = System.currentTimeMillis() + time;
                long remaining = time;
                while (notStart && remaining>0){  // 5秒之内没有人改变notStart状态就抛出异常
                    try{
                        System.out.println("不满足条件");
                        lock.wait(remaining);
                        remaining = future-System.currentTimeMillis();
                    }catch (InterruptedException e){
                    }
                }
                if (remaining<=0){
                    throw  new Exception("ssss");
                }
                System.out.println("满足条件,开始执行业务逻辑");
            }
        }
    }

    public static void testTimeWait() throws InterruptedException {
        Thread wait = new Thread(new WaitTimeThread(),"wait");
        wait.start();
    }


    public static void main(String[] args) throws InterruptedException {
        testTimeWait();
    }
}
