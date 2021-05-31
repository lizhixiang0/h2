package com.zx.arch.spring.annotation;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * @author lizx
 * @since 1.0.0
 * @description   @Order 注解可以控制bean加载优先级，默认是最低优先级
 * @blog "https://www.jianshu.com/p/37edf9389814
 * @Test  在AppScan中使用过,杰哥创建了个工厂类，需要将上下文中的某些对象放到工厂中去，此时就给这个工厂类加了个@order ，保证最后注册这个工厂对象
 **/

@Order
@Component
public class OrderTest {
    @Order(1)
    public class Order1Test{}
    @Order(2)
    public class Order2Test{}
}
