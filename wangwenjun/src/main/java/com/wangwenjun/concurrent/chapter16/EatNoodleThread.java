package com.wangwenjun.concurrent.chapter16;

/**
 * 这就是著名的哲学家进餐问题：如果两个人都先拿左边的餐具，则大几率出现死锁！ （注意两个人相对而坐,A的左边是刀,B的左边是叉）
 * 解决方案：
 *          1、加独占锁,单线程模式，一次只能一个人去吃
 *          2、设置两个人都先拿叉子，拿到叉子再去拿刀
 * @author admin
 */
public class EatNoodleThread extends Thread {
    private final String name;

    private final TablewarePair tablewarePair;

    public EatNoodleThread(String name, TablewarePair tablewarePair) {
        this.name = name;
        this.tablewarePair = tablewarePair;
    }

    @Override
    public void run() {
        for (int i = 0 ;i<10000000;i++){
            this.eat_2();
        }
    }

    /**
     * 58062
     */
    private void eat_1() {
        // 锁住整双筷子
        synchronized (tablewarePair) {
            System.out.println(name + " is eating now.");
        }
    }

    /**
     * 58900
     * 这种方式似乎和锁住整个资源是一样的
     * 经过测试，效率相差不大，具体原因猜测与锁升级相关，以后再来补充
     */
    private void eat_2(){
        // 先锁一个餐具
        synchronized (tablewarePair.getLeftTool()) {
            // 再锁一个餐具
            synchronized (tablewarePair.getRightTool()){
                System.out.println(name + " is eating now.");
            }
        }
    }


}