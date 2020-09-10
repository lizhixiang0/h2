package com.zx.arch.parameter;

/**
 * @author lizx
 * @since 1.0.0
 * @测试参数传递
 **/
public class Test {

    public static void testParameter(People people){
        people.setName("sss");
    }

    public static void main(String[] args) {
        People people = new People();
        testParameter(people);
        System.out.println(people.getName());
        //得出结论: 传递对象时，可以对对象进行操作!因为传递的是地址，对地址进行操作最终还是同一个对象！
    }
}
