package com.zx.arch.threads;

import java.lang.reflect.Field;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

/**
 * @author lizx
 * @since 1.0.0
 * @description 1、ThreadLocal是什么?
 *              2、ThreadLocal怎么用?
 *              3、ThreadLocal源码分析?
 *              4、ThreadLocal内存泄漏问题?
 *               内存泄漏memory leak ：是指程序在申请内存后，无法释放已申请的内存空间，一次内存泄漏似乎不会有大的影响，但内存泄漏堆积后的后果就是内存溢出。
 *               内存溢出 out of memory ：没内存可以分配给新的对象了。
 **/
public class ThreadLocalTest {
    /**
     * 简单了解
     * @blog  "https://baijiahao.baidu.com/s?id=1653790035315010634&wfr=spider&for=pc
     */
    private static void a(){
        ThreadLocal<String> local = new ThreadLocal<>();
        Random random = new Random();
        IntStream.range(0,5).forEach(a->new Thread(()->{
            local.set(a +"    "+random.nextInt(10));
            System.out.println("线程和local值分别是"+local.get());
        }).start());
    }

    /**
     * 内存泄露测试
     * @blog "https://blog.csdn.net/thewindkee/article/details/103726942"
     * @note "https://blog.csdn.net/thewindkee/article/details/89390145
     *       我比较赞成这个作者的话！
     *       ThreadLocal内存泄漏的根源是：
     *       由于ThreadLocalMap的生命周期跟Thread一样长，如果没有手动删除对应key的value就会导致内存泄漏，而不是因为弱引用。
     */
    private static void b() throws NoSuchFieldException, IllegalAccessException {
        ThreadLocal<Object> threadLocal = ThreadLocal.withInitial(String::new);
        threadLocal.set("test");
        //threadLocal = null;//失去对threadLocal的强引用 ,help gc
        Thread thread = Thread.currentThread();
        print(thread);
        // 手动gc
        System.gc();
        //threadLocal.remove();
        thread = Thread.currentThread();
        print(thread);

    }


    /**
     * 打印threadLocalMap信息
     */
    public static void print(Thread thread) throws NoSuchFieldException, IllegalAccessException {
        Class<? extends Thread> clazz = thread.getClass();
        Field field = clazz.getDeclaredField("threadLocals");
        field.setAccessible(true);
        Object threadLocalMap = field.get(thread);
        Class<?> temp = threadLocalMap.getClass();
        Field tempField = temp.getDeclaredField("table");
        tempField.setAccessible(true);
        Object[] arr = (Object[]) tempField.get(threadLocalMap);
        for(Object o :arr){
            if(Objects.nonNull(o)){
                Class<?> entry = o.getClass();
                Field referent = entry.getSuperclass().getSuperclass().getDeclaredField("referent");
                referent.setAccessible(true);
                Field entryValue = entry.getDeclaredField("value");
                entryValue.setAccessible(true);
                System.out.println(String.format("弱引用key:%s,值:%s",referent.get(o),entryValue.get(o)));
            }
        }
        System.out.println("\r\n\r\n");
    }

    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException {
        b();
    }
}
