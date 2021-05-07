package com.zx.arch.designer.observer.v4;

/**
 * 4、加入多个观察者
 */

class Child {
    private boolean cry = false;
    private Dad dad = new Dad();
    private Mum mum = new Mum();
    private Dog dog = new Dog();


    public boolean isCry() {
        return cry;
    }

    public void wakeUp() {
        cry = true;
        // 这里不好,耦合度太高
        dad.feed();
        dog.wang();
        mum.hug();
    }
}

class Dad {
    public void feed() {
        System.out.println("dad feeding...");
    }
}

class Mum {
    public void hug() {
        System.out.println("mum hugging...");
    }
}

class Dog {
    public void wang() {
        System.out.println("dog wang...");
    }
}

/**
 * @author admin
 */
public class Main {
    public static void main(String[] args) {
        Child c = new Child();
        //do sth
        c.wakeUp();
    }
}
