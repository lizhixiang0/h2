package lang.annotation;

import lombok.Data;

/**
 * @author lizx
 * @date 2021/9/16
 * @since FunctionalInterface注释了解
 **/
@Data
public class FunctionalInterfaceTest {

        /*
            1、该注解只能标记在"有且仅有一个抽象方法"的接口上。

            2、JDK8接口中的静态方法和默认方法，都不算是抽象方法。

            3、接口默认继承java.lang.Object，所以如果接口显示声明覆盖了Object中方法，那么也不算抽象方法。

            4、该注解不是必须的，如果一个接口符合"函数式接口"定义，那么加不加该注解都没有影响。加上该注解能够更好地让编译器进行检查。如果编写的不是函数式接口，但是加上了@FunctionInterface，那么编译器会报错。

            5、函数接口的实例可以用lambda表达式、方法引用或构造函数引用创建。
        */

        public  String name = "FunctionalInterfaceTest";

        public void test1(){
            TestInterface<FunctionalInterfaceTest> testTestInterface = test -> {test.setName(test.name.substring(1)); };
            testTestInterface.sub(new FunctionalInterfaceTest());
        }

    public static void main(String[] args) {
        new FunctionalInterfaceTest().test1();
    }
}


/**
 * 正确的函数式接口
 */
@FunctionalInterface
interface TestInterface<T> {


    /**
     * 抽象方法
     */
    void sub(T t);

    /**
     * Object中的方法不是抽象方法
     * @param var1
     * @return
     */
    @Override
    boolean equals(Object var1);

    /**
     * default方法
     */
    default void defaultMethod() {}

    /**
     * static方法
     */
    static void staticMethod() {}
}