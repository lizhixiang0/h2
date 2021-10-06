package com.zx.arch.concurrency;

/**
 * @author lizx
 * @date 2021/9/22
 * @since
 **/
public class ThreadPrintDemo {

        static int num = 0;
        static volatile boolean flag = false;

        public static void main(String[] args){

            Thread t1 = new Thread(() -> {
                for (; 100 > num; ) {
                    if (!flag && (num == 0 || ++num % 2 == 0)) {
                        System.out.println(num);
                        flag = true;
                    }
                }
            }
            );

            Thread t2 = new Thread(() -> {
                for (; 100 > num; ) {
                    if (flag && (++num % 2 != 0)) {
                        System.out.println(num);
                        flag = false;
                    }
                }
            }
            );

            t1.start();
            t2.start();
        }
}
