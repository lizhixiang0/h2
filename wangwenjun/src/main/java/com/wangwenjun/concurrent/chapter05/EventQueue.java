package com.wangwenjun.concurrent.chapter05;

import java.util.LinkedList;

import static java.lang.Thread.currentThread;

/**
 *
 * 同步阻塞和异步非阻塞的区别
 * 
 * 同步阻塞: 外宾访问,来一个外宾就得搞一个线程来接待， 不能让人家等着
 * 
 * 异步非阻塞:KFC,单线程负责接待(发号,检查号是否好)，后面配一个线程池 。 线程池如何知道有顾客需要解决,一般是两种方法，一种是轮询，一种是服务员去通知，
 *           这里我们使用通知,从而引申出线程之间的通信
 * 
 * @author admin
 */
public class EventQueue {

    private final int max;

    static class Event {
    }

    private final LinkedList<Event> eventQueue = new LinkedList<>();

    private final static int DEFAULT_MAX_EVENT = 10;

    public EventQueue() {
        this(DEFAULT_MAX_EVENT);
    }

    public EventQueue(int max) {
        this.max = max;
    }

    public void offer(Event event) {
        synchronized (eventQueue) {
            while (eventQueue.size() >= max) {
                try {
                    console(" the queue is full.");
                    eventQueue.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            console(" the new event is submitted");
            eventQueue.addLast(event);
            eventQueue.notifyAll();
        }
    }

    public Event take() {
        synchronized (eventQueue) {
            while (eventQueue.isEmpty()) {
                try {
                    console(" the queue is empty.");
                    eventQueue.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            Event event = eventQueue.removeFirst();
            this.eventQueue.notifyAll();
            console(" the event " + event + " is handled.");
            return event;
        }
    }

    private void console(String message) {
        System.out.printf("%s:%s\n", currentThread().getName(), message);
    }
}
