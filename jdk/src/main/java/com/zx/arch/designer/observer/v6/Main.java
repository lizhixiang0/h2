package com.zx.arch.designer.observer.v6;

import java.util.ArrayList;
import java.util.List;

/**
 * 6、有很多时候，不同的观察者需要根据事件的具体情况来进行处理，将孩子的状态封装成事件对象，然后传递给不同的观察者，观察者自己内部去根据状态采取行动
 */

class Child {
    private boolean cry = false;
    private List<Observer> observers = new ArrayList<>();

    {
        observers.add(new Dad());
        observers.add(new Mum());
        observers.add(new Dog());
    }


    public boolean isCry() {
        return cry;
    }

    public void wakeUp() {
        if(cry){
            // 通常来讲,被观察者会有多种状态,所以需要将其抽象出来,这里用一个事件类表示
            wakeUpEvent event = new wakeUpEvent(System.currentTimeMillis(), "bed");
            for(Observer o : observers) {
                o.actionOnWakeUp(event);
            }
        }
    }
}

class wakeUpEvent{
    long timestamp;
    String loc;

    public wakeUpEvent(long timestamp, String loc) {
        this.timestamp = timestamp;
        this.loc = loc;
    }
}

interface Observer {
    void actionOnWakeUp(wakeUpEvent event);
}

class Dad implements Observer {
    public void feed() {
        System.out.println("dad feeding...");
    }

    @Override
    public void actionOnWakeUp(wakeUpEvent event) {
        feed();
    }
}

class Mum implements Observer {
    public void hug() {
        System.out.println("mum hugging...");
    }

    @Override
    public void actionOnWakeUp(wakeUpEvent event) {
        hug();
    }
}

class Dog implements Observer {
    public void wang() {
        System.out.println("dog wang...");
    }

    @Override
    public void actionOnWakeUp(wakeUpEvent event) {
        wang();
    }
}

public class Main {
    public static void main(String[] args) {
        Child c = new Child();
        //do sth
        c.wakeUp();
    }
}
