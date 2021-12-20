package com.wangwenjun.concurrent.chapter03;

import java.util.stream.IntStream;

/**
 * @author admin
 */
public class Yield {

    private static Thread create(int index) {
        return new Thread(() -> {
            System.out.println(index);
            // 提示cpu调度器自己可以释放持有的cpu资源,但cpu有可能置之不理
            Thread.yield();
            System.out.println(index);

        });
    }

    public static void main(String[] args) {
        IntStream.range(0, 2)
                .mapToObj(Yield::create)
                .forEach(Thread::start);
    }
}