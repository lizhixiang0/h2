package com.zx.arch.spring.annotation;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * @author lizx
 * @since 1.0.0
 * @description   @Order 注解可以控制bean加载优先级，默认是最低优先级
 * @blog "https://www.jianshu.com/p/37edf9389814
 **/

@Order
@Component
public class OrderTest {
    @Order(1)
    public class Order1Test{}
    @Order(2)
    public class Order2Test{}
}
