package com.zx.arch.jdk;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * @author lizx
 * @since 1.0.0
 * @description 工作中的一点疑问
 **/
@ToString
public class TryCatchFinally {
    @Setter
    @Getter
    private String a;
    /**
     * 调用的doIt()里面使用了try catch ,在catch里抛出了异常,探讨执行顺序
     */
    static void test() {
        try {
            System.out.println("1 outer try");
            doIt();
        } catch (Exception e){
            System.out.println("5 outer catch");
            // swallow
        } finally {
            System.out.println("6 outer finally");
        }
    }

    /**
     * doIt 里面的catch会抛出异常的,外面正常调用
     * 其实try catch finally 中catch ！！但是此时try 和 finally必须都写！
     */
    static void test1() {
            doIt();
    }


    static void doIt() {
        try {
            System.out.println("2 inner try");
            int i = 0;
            System.out.println(12 / i);
        } catch (Exception e) {
            System.out.println("3 inner catch");
            throw e;
        } finally {
            System.out.println("4 inner finally");
        }
    }

    /**
     * java面试题--如果catch里面有return语句，finally里面的代码还会执行吗？
     * 会执行！！但是catch中回路已经形成！
     */
    public static TryCatchFinally getInt() {
        TryCatchFinally a= new TryCatchFinally();
        a.setA("10");
        try {
            System.out.println(1 / 0);
            a.setA("20");
        } catch (ArithmeticException e) {
            a.setA("30");
            System.out.println("exec1");
            /*
             * 如果这里a是基本类型或者字符类型，那return a 在程序执行到这一步的时候，这里不是return a 而是 return "30"；
             * 这个返回路径已经形成了，这里的a就不是a变量了，而是具体的数据、字面量。就算它发现后面还有finally，a=40,但再次回到以前的路径,还是继续走return 30。
             * 但是如果这里a是个具体的对象！！那就另当别论，在finally里操作的是原对象，无论他被传递到哪里去，引用是不会变的！！！
             *
             */
            return a;
        } finally {
            a.setA("40");
            System.out.println("exec2");
        }
        return a;
    }

    /**
     * 如果在catch和finally里都有return ,以哪个为准？？
     * 以finally !
     */
    public static String getInt1() {
        String  a= "10";
        try {
            System.out.println(1 / 0);
            a="20";
        } catch (ArithmeticException e) {
            a="30";
            System.out.println("exec1");
            return a;
        } finally {
            a="40";
            System.out.println("exec2");
            // 如果这样，就又重新形成了一条返回路径，由于只能通过1个return返回，所以这里直接返回40
            return a;
        }
    }



    public static void main(String[] args) {
        System.out.println(getInt1());
    }
}
