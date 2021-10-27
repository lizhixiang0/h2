package util.concurrent.atomic;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicStampedReference;

/**
 * @author lizx
 * @date 2021/10/15
 * @since CAS��ABA�������
 * @blog ��https://blog.csdn.net/Coder_xh/article/details/88889073
 **/
public class AtomicStampedReferenceTest {

    private static void testABA(){
        /**
         * ԭ�Ӷ����aba����
         */
        AtomicInteger index = new AtomicInteger(10);
        new Thread(() -> {
            index.compareAndSet(10, 11);
            index.compareAndSet(11, 10);
            System.out.println(Thread.currentThread().getName()+"�� 10->11->10");
        },"����").start();

        new Thread(() -> {
            try {
                TimeUnit.SECONDS.sleep(2);
                boolean isSuccess = index.compareAndSet(10, 12);
                System.out.println(Thread.currentThread().getName()+"�� index��Ԥ�ڵ�10�"+isSuccess+"   ���õ���ֵ�ǣ�"+index.get());
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        },"����").start();
    }

    private static void solveABA(){

        int initialRef = 10;

        int initialStamp = 1;
        /**
         * �����汾��ԭ�����ö���,����ֵΪ10�����԰汾��Ϊ1
         * stamp ���ӡ�ӡ��
         */
        AtomicStampedReference<Integer> stampRef = new AtomicStampedReference(initialRef, initialStamp);

        new Thread(() -> {
                System.out.println(Thread.currentThread().getName()+ " �汾�ţ� " + stampRef.getStamp());
                stampRef.compareAndSet(initialRef, initialRef+1,stampRef.getStamp(),stampRef.getStamp()+1);
                System.out.println(Thread.currentThread().getName()+ " �汾�ţ� " + stampRef.getStamp());
                stampRef.compareAndSet(11, initialRef,stampRef.getStamp(),stampRef.getStamp()+1);
                System.out.println(Thread.currentThread().getName()+ " �汾�ţ� " + stampRef.getStamp());
        },"����").start();


        new Thread(() -> {
            try {
                TimeUnit.SECONDS.sleep(1);
                // �޸Ļ�ʧ��,��Ȼֵ���ǳ�ʼֵ,���ǰ汾�Ų�����Ԥ��
                boolean isSuccess =stampRef.compareAndSet(initialRef, initialRef+1,initialStamp,stampRef.getStamp()+1);
                System.out.println(Thread.currentThread().getName()+ " �޸��Ƿ�ɹ��� "+ isSuccess+" ��ǰʵ��ֵ�� " + stampRef.getReference()+" ��ǰ�汾 ��" + stampRef.getStamp());
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        },"����").start();
    }




    public static void main(String[] args) {
        solveABA();
    }

}
