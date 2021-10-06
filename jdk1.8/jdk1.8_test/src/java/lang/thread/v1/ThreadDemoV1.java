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
        // ���java�̹߳���MxBean
        ThreadMXBean threadMXBean = ManagementFactory.getThreadMXBean();
        // ����Ҫ���monitor��synchronizer��Ϣ
        ThreadInfo[] threadInfos = threadMXBean.dumpAllThreads(false, false);
        for (ThreadInfo threadInfo: threadInfos){
            System.out.println("["+threadInfo.getThreadId()+"]"+ threadInfo.getThreadName());
        }

        /*
            [6]Monitor Ctrl-Break           idea�����е��̣߳�https://www.jianshu.com/p/2cfd551055d7
            [5]Attach Listener              ������պͷ����ⲿ��jvm����
            [4]Signal Dispatcher            �����źŸ�jvm���߳�
            [3]Finalizer                    ��Ҫ�����������ռ�ǰ�����ö����finalize()����
            [2]Reference Handler            ���ڴ������ö����������á������á������ã���������������
            [1]main                         �û��߳����
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
            System.out.println("Job priority : " + job.priority + " , count�� " + job.jobCount);
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
                Thread.yield(); // �����������,�ȴ�cpu����
            }
            while (notEnd){
                Thread.yield(); // �����������
                jobCount++;
            }
        }
    }

    /**
     * ��һ��java������в����ڷ�Daemon�̵߳�ʱ��JAVA����������˳���
     * java������˳�ʱ��Daemon�߳��е�finally�鲻һ��ִ��,���Բ���ʹ��daemon�߳����ر���Դ (һ������User Thread�뿪�ˣ������Ҳ���˳�������,��ʱ�ػ��̲߳�һ�����ü�ִ��)
     * https://blog.csdn.net/shimiso/article/details/8964414
     */
    public static void testDaemonThread(){
        Thread thread = new Thread(new DaemonThread());
        thread.setDaemon(true); // setDeamon(true)��Ψһ������Ǹ���JVM����Ҫ�ȴ����˳�,��JVMϲ��ʲô�˳����˳���,���ù���
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
     * ���̴߳��ڡ�waiting, sleeping���������������еĹ����У�������ж��ˣ��Ϳ����׳�InterruptedException�쳣,ͬʱ���쳣�׳��󣬵�ǰ�̵߳��ж�״̬Ҳ�ᱻ�����
     * �жϲ�����ֱ�ӽ�һ���߳�ͣ�����ڱ��жϵ��̵߳ĽǶȿ������������Լ����жϱ�־λ����Ϊtrue�ˣ������Լ���ִ�еĴ������׳���һ��InterruptedException�쳣�����˶��ѡ�
     * @throws InterruptedException
     */
    public static  void testInterrupt() throws InterruptedException {
        Thread thread = new Thread(new DaemonThread(),"interrupt");
        thread.start();
        TimeUnit.SECONDS.sleep(4);


        thread.interrupt(); // �����ж��ź�,�̴߳�ʱ����sleep״̬�����Ի��׳��쳣����������жϱ�ʶ
        TimeUnit.SECONDS.sleep(5);

        System.out.println(thread.isInterrupted());

    }

    static class WaitThread implements Runnable {

        @Override
        public void run() {
            synchronized (lock) {  // ������
                while (notStart){ // �������ʹ��while,�̱߳����Ѻ󣬻�Ҫ�������״̬�Ƿ����Ҫ��!
                    try{
                        System.out.println("����������");
                        lock.wait(); // �ѵ�ǰ�̼߳ӵ�������ĵȴ�������ȥ
                        System.out.println("����");  // �̱߳����Ѻ����ִ��
                    }catch (InterruptedException e){
                    }
                }
                System.out.println("��������,��ʼִ��ҵ���߼�");
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
         * ����5sû��ִ�о����쳣
         */
        private static long  time = 5000;

        @SneakyThrows
        @Override
        public void run() {
            synchronized (lock) {
                long future  = System.currentTimeMillis() + time;
                long remaining = time;
                while (notStart && remaining>0){  // 5��֮��û���˸ı�notStart״̬���׳��쳣
                    try{
                        System.out.println("����������");
                        lock.wait(remaining);
                        remaining = future-System.currentTimeMillis();
                    }catch (InterruptedException e){
                    }
                }
                if (remaining<=0){
                    throw  new Exception("ssss");
                }
                System.out.println("��������,��ʼִ��ҵ���߼�");
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
