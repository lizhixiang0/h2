package com.zx.arch.designer.observer.v5;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 5、使用多态,将观察者与被观察者解耦合
 */

class Child {
    private boolean cry = false;
    private List<Observer> observers = new ArrayList<>();

    {
        observers.add(new Dog());
    }

    public void addObserver(Observer observer){
        observers.add(observer);
    }

    public boolean isCry() {
        return cry;
    }

    public void wakeUp() {
        cry = true;
        // 这里和责任链模式有点像,通常观察者模式会和责任链模式一起用
        for(Observer o : observers) {
            o.actionOnWakeUp();
        }
    }
}

interface Observer {
    void actionOnWakeUp();
}

class Dad implements Observer {
    public void feed() {
        System.out.println("dad feeding...");
    }

    @Override
    public void actionOnWakeUp() {
        feed();
    }
}

class Mum implements Observer {
    public void hug() {
        System.out.println("mum hugging...");
    }

    @Override
    public void actionOnWakeUp() {
        hug();
    }
}

class Dog implements Observer {
    public void wang() {
        System.out.println("dog wang...");
    }

    @Override
    public void actionOnWakeUp() {
        wang();
    }
}

public class Main {
    public static void main(String[] args) {
        Child c = new Child();
        c.addObserver(new Dad());
        c.addObserver(new Mum());
        //do sth
        c.wakeUp();
    }
}
