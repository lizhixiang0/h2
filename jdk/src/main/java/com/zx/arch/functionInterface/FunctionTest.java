package com.zx.arch.functionInterface;

import com.zx.arch.jvm.CacheLinePadding;

import java.util.function.Consumer;

/**
 * @author lizx
 * @date 2021/11/29
 * @since
 * @description jdk1.8 推出的函数式接口,装逼必会，记住这个就是个语法糖 ! 以后写代码可以尝试用用这些！
 * @blog "https://mp.weixin.qq.com/s/YO7n8qGvjAOKeG_vkbmxsA
 *       "https://juejin.cn/post/7011435192803917831
 *
 *
 *  JDK中常见的函数式接口使用主要分为四种： 函数式接口只能有一个抽象方法
 *
 *      Supplier供给型函数： 抽象方法不接受参数,只返回数据,可以用来提供保底对象
 *      Consumer消费型函数：抽象方法接收一个参数,没有返回值
 *      Runnable无参无返回型函数
 *      Function有参有返回型函数,例如 Predicate  https://www.cnblogs.com/qdhxhz/p/11323595.html
 **/
@FunctionalInterface
public interface FunctionTest {
    void test();
}

@FunctionalInterface
interface ThrowExceptionFunction {

    /**
     * 用来抛出异常信息
     *
     * @param message 异常信息
     * @return void
     **/
    void throwMessage(String message);
}

@FunctionalInterface
interface BranchHandle {

    /**
     * 用来处理分支操作
     *
     * @param trueHandle 为true时要进行的操作
     * @param falseHandle 为false时要进行的操作
     * @return void
     **/
    void trueOrFalseHandle(Runnable trueHandle, Runnable falseHandle);
}

interface PresentOrElseHandler<T extends Object> {

    /**
     * 值不为空时执行消费操作,否则执行其他的操作
     *
     * @param action 值不为空时，执行的消费操作
     * @param emptyAction 值为空时，执行的操作
     * @return void
     **/
    void presentOrElseHandle(Consumer<? super T> action, Runnable emptyAction);
}

interface PredicateFunction{
    boolean test(int  t);
}




class VUtils{

    /**
     *
     * @param b
     * @return 返回值是一个函数式对象
     */
    public static ThrowExceptionFunction isTrue(boolean b){
        return (errorMessage) -> {
            if (b){
                throw new RuntimeException(errorMessage);
            }
        };
    }

    /**
     *
     * @param b
     * @return  返回值是一个函数式对象
     */
    public static BranchHandle isTrueOrFalse(boolean b){

        return (trueHandle, falseHandle) -> {
            if (b){
                trueHandle.run();
            } else {
                falseHandle.run();
            }
        };
    }

    /**
     * 参数为true或false时，分别进行不同的操作
     *
     * @param
     * @return 返回值是一个函数式对象
     **/
    public static PresentOrElseHandler<?> isBlankOrNoBlank(String str){

        return (consumer, runnable) -> {
            if (str == null || str.length() == 0){
                runnable.run();
            } else {
                consumer.accept(str);
            }
        };
    }

    /**
     *
     * @return 返回值是一个函数式对象
     */
    public static PredicateFunction isParamUseful(int s){
        return x -> x+s > 7;
    }

    public static void main(String[] args) {
        VUtils.isTrue(true).throwMessage("我草无情");

        VUtils.isTrueOrFalse(true).trueOrFalseHandle(
                ()->{
                    System.out.println("我草无情1");
                },
                ()->{
                    System.out.println("我草无情2");
                }
        );

        VUtils.isBlankOrNoBlank("我草无情3").presentOrElseHandle(
                System.out::println,
                ()->{
                    System.out.println("我草无情4");
                }
        );

        System.out.println(VUtils.isParamUseful(1).test(2));

    }
}

