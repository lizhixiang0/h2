package com.wangwenjun.concurrent.chapter09;

import java.util.Random;
import java.util.stream.IntStream;

/**
 *
 * 类的加载过程主要分为三个阶段：
 *  1、加载阶段，查找并加载类的二进制文件
 *  2、连接阶段，细分为三个,验证、准备、解析
 *  3、初始化阶段，为类的静态变量赋予正确的初始值,类的初始化阶段会调用一个clinit方法，这个方法是在编译阶段生成的，里面包括了所有类变量的赋值动作和静态代码块的执行代码
 *  *              注意：静态代码块可以对后面的变量进行赋值，但不能进行访问
 *
 *  简单来讲：类的加载就是将class文件中的二进制数据读取到内存之后，将该字节流所代表的的静态存储结构转化为方法区中运行时的数据结构
 *  并且在堆区生成一个该类的java.lang.class对象，最为访问该数据结构的入口 ！
 *  类加载的最终产物就是堆内存中的class对象，对于同一个classloader来讲，无论一个类被new多少次，对应堆中的class对象始终就是同一个
 *
 * 说一说触发JVM进行类的加载和初始化的六种情况 （）
 * 1. 使用 New 关键字实例化对象的时候。
 * 2. 读取或设置一个类的静态字段的时候。  (不包括静态常量,即加了final的字段，静态常量在编译阶段就完成了赋值)
 * 3. 调用一个类的静态方法的时候。
 * 4. 通过java.lang.reflect包中的方法对类进行反射调用的时候。
 * 5. 当初始化一个类时，发现其父类还没有进行初始化，则需要先触发其父类初始化。
 * 6. 当虚拟机启动时，用户需要指定一个要执行的包含 main 方法的主类，虚拟机会初始化这个主类。
 *
 * @author admin
 */
public class Simple
{
    static
    {
        System.out.println("I will be initialized");
    }

    /**
     * 静态常量在编译阶段就完成了赋值,所以不会出发初始化
     */
    public final static int CONST = 10;
    /**
     * RANDOM虽然是个静态常量，但由于计算复杂，需要在初始化之后才能得到结果，所以其他类访问RANDOM也会导致类的初始化
     */
    public final static int RANDOM = new Random().nextInt();

    public static void main(String[] args) {
        // 这种数组定义形式不会导致类的初始化
        Simple[] simples = new Simple[10];

        // 静态代码块中的代码只有在第一次加载类时才会执行,所以只会打印一次
        IntStream.range(0, 5).forEach(i -> new Thread(Simple::new));
    }


}
