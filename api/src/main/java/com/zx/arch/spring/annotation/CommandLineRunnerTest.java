package com.zx.arch.spring.annotation;

import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * @author lizx
 * @since 1.0.0
 * @see org.springframework.boot.CommandLineRunner
 * @description  SpringBoot提供了一个简单的方式来实现Bean数据的预加载,可以配合spring的@Order注解来使用
 * @Blog    "https://blog.csdn.net/ruben95001/article/details/78340700
 **/
@Order
@Component
public class CommandLineRunnerTest implements CommandLineRunner {
    @Override
    public void run(String... args) throws Exception {

    }
}
