package com.wangwenjun.concurrent.chapter03;


public class Priority {

    /**
     * 测试线程的优先级设置
     * 这是个提示操作，理论上优先级高更容易获得时间片
     * cpu繁忙时，设置优先级可能会获得更多时间片,空闲时差距不大
     */
    public static void test_priority() {
        Thread t1 = new Thread(() ->
        {
            while (true) {
                System.out.println("t1");
            }
        });
        // 设置t1优先级为3
        t1.setPriority(3);

        Thread t2 = new Thread(() ->
        {
            while (true) {
                System.out.println("t2");
            }
        });
        // 设置t1优先级为10
        t2.setPriority(10);

        t1.start();
        t2.start();
    }

    public static void test_parent_and_group_priority(){
        // 子线程继承父线程优先级
        Thread t2 = new Thread(() ->
        {
            Thread t3 = new Thread();
            System.out.println("t3 priority " + t3.getPriority());
        });

        t2.setPriority(6);
        t2.start();
        System.out.println("t2 priority " + t2.getPriority());

        // 组内线程最大优先级为组线程优先级
        ThreadGroup group = new ThreadGroup("test");
        group.setMaxPriority(7);

        Thread thread = new Thread(group, "test-thread");
        thread.setPriority(10);

        System.out.println(thread.getPriority());
    }

    public static void main(String[] args) {
        test_parent_and_group_priority();
    }
}