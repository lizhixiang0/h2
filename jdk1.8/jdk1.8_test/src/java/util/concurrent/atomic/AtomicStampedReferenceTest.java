package util.concurrent.atomic;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicStampedReference;

/**
 * @author lizx
 * @date 2021/10/15
 * @since CAS的ABA问题测试
 * @blog ‘https://blog.csdn.net/Coder_xh/article/details/88889073
 **/
public class AtomicStampedReferenceTest {

    private static void testABA(){
        /**
         * 原子对象的aba问题
         */
        AtomicInteger index = new AtomicInteger(10);
        new Thread(() -> {
            index.compareAndSet(10, 11);
            index.compareAndSet(11, 10);
            System.out.println(Thread.currentThread().getName()+"： 10->11->10");
        },"张三").start();

        new Thread(() -> {
            try {
                TimeUnit.SECONDS.sleep(2);
                boolean isSuccess = index.compareAndSet(10, 12);
                System.out.println(Thread.currentThread().getName()+"： index是预期的10嘛，"+isSuccess+"   设置的新值是："+index.get());
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        },"李四").start();
    }

    private static void solveABA(){

        int initialRef = 10;

        int initialStamp = 1;
        /**
         * 创建版本号原子引用对象,初试值为10、初试版本号为1
         * stamp 戳子、印记
         */
        AtomicStampedReference<Integer> stampRef = new AtomicStampedReference(initialRef, initialStamp);

        new Thread(() -> {
                System.out.println(Thread.currentThread().getName()+ " 版本号： " + stampRef.getStamp());
                stampRef.compareAndSet(initialRef, initialRef+1,stampRef.getStamp(),stampRef.getStamp()+1);
                System.out.println(Thread.currentThread().getName()+ " 版本号： " + stampRef.getStamp());
                stampRef.compareAndSet(11, initialRef,stampRef.getStamp(),stampRef.getStamp()+1);
                System.out.println(Thread.currentThread().getName()+ " 版本号： " + stampRef.getStamp());
        },"张三").start();


        new Thread(() -> {
            try {
                TimeUnit.SECONDS.sleep(1);
                // 修改会失败,虽然值还是初始值,但是版本号不符合预期
                boolean isSuccess =stampRef.compareAndSet(initialRef, initialRef+1,initialStamp,stampRef.getStamp()+1);
                System.out.println(Thread.currentThread().getName()+ " 修改是否成功： "+ isSuccess+" 当前实际值： " + stampRef.getReference()+" 当前版本 ：" + stampRef.getStamp());
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        },"李四").start();
    }




    public static void main(String[] args) {
        solveABA();
    }

}
