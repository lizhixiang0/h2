package util.concurrent.locks;

import java.util.concurrent.locks.LockSupport;

/**
 * @author lizx
 * @date 2021/10/11
 * @since
 * @description  LockSupport是一个线程工具类，所有的方法都是静态方法，可以让线程在任意位置阻塞，也可以在任意位置唤醒
 *               有点类似wait/notify,但是有两点区别
 *               1、wait和notify都是Object中的方法,在调用这两个方法前必须先获得锁对象，但是park不需要获取某个对象的锁
 *               2、notify只能随机选择一个线程唤醒，无法唤醒指定的线程，unpark却可以唤醒一个指定的线程。
 *               3、都会响应interrupt中断，wait是抛出一个中断异常 InterruptedException，LockSupport是结束park,不会抛出异常
 * @blog 'https://baijiahao.baidu.com/s?id=1666548481761194849&wfr=spider&for=pc
 **/
public class LockSupportTest {
    public static class DemoThread extends Thread {
        @Override
        public void run() {
            System.out.println(getName() + "进入线程");
            LockSupport.unpark(this); // park/unpark 使用时没有先后顺序
            LockSupport.park();
            System.out.println(getName() + "线程运行结束");
        }
    }

    public static void main(String[] args) {
        DemoThread demoThread = new DemoThread();

        demoThread.start();
        System.out.println("demoThread线程已经启动");

        System.out.println("主线程结束");
        demoThread.interrupt();
    }
}
