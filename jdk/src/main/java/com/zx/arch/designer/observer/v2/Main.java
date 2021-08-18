package com.zx.arch.designer.observer.v2;

/**
 * 2、稍微高级点了,使用面向对象，将小孩封装出来,将孩子的状态封装成属性，通过方法调用查看
 */
class Child {
    private boolean cry = false;

    public boolean isCry() {
        return cry;
    }

    public void wakeUp() {
        System.out.println("Waked Up! Crying wuwuwuwu...");
        cry = true;
    }
}

/**
 * @author admin
 */
public class Main {
    public static void main(String[] args) {
        Child child = new Child();

        while(!child.isCry()) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("observing...");
        }

    }
}
