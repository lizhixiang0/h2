package com.zx.arch.designer.observer.v7;

import java.util.ArrayList;
import java.util.List;

/**
 * 7、除了可以将被观察者的状态分装到事件对象中，还可以将被观察者本身也放进去
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
        cry = true;
        // 大多数时候，我们处理事件的时候，需要事件源对象（需要源对象的资源或者需要看源对象的类别）,将事件原对象放到event里面去，然后传递给Observer
        wakeUpEvent event = new wakeUpEvent(System.currentTimeMillis(), "bed", this);
        for(Observer o : observers) {
            o.actionOnWakeUp(event);
        }
    }
}

class wakeUpEvent{
    long timestamp;
    String loc;
    Child source;

    public wakeUpEvent(long timestamp, String loc, Child source) {
        this.timestamp = timestamp;
        this.loc = loc;
        this.source = source;
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