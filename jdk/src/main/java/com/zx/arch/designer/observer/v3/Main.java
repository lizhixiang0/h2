package com.zx.arch.designer.observer.v3;

/**
 * 3、在小孩（被观察者）内部加入dad(观察者)
 */

class Child {
    private boolean cry = false;
    /**
     * 观察者放到被观察者里面
     */
    private Dad d = new Dad();

    public boolean isCry() {
        return cry;
    }

    public void wakeUp() {
        // 将处理方法直接放在wakeUp里,哭了就喂食
        if(cry) {
            d.feed();
        }
    }
}

class Dad {
    public void feed() {
        System.out.println("dad feeding...");
    }
}

public class Main {
    public static void main(String[] args) {
        Child c = new Child();
        // 对小孩做一些操作
        c.wakeUp();
    }
}
