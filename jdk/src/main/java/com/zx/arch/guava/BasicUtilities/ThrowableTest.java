package com.zx.arch.guava.BasicUtilities;

import com.google.common.base.Throwables;

import java.io.IOException;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @blog  "http://ifeve.com/google-guava-throwables/"
 * @note  辅助理解 https://www.cnblogs.com/peida/p/Guava_Throwables.html
 **/
public class ThrowableTest {

    /**
     * 为什么我们要这么麻烦？
     * 通常我们直接抛出异常即可，但是如果需要对异常做相关处理，比如统计异常！
     * 那就需要拿到异常，处理后再重新抛出去！
     */
    public static void a(){
        throw new ArrayIndexOutOfBoundsException();
    }

    /**
     * 已知是什么异常。例如NPP异常。统计完再次抛出
     * throwIfInstanceOf()
     * Throwable类型为指定的异常才抛出,指定数组异常才抛出,所以这里会抛出  （这个不管是受检还是不受检）
     */
    public static void b() throws IOException {
        try {
            throw new NullPointerException();
        } catch (Throwable t) {
            //重新抛出
            Throwables.throwIfInstanceOf(t,NullPointerException.class);
            Throwables.throwIfInstanceOf(t,IOException.class);
        }
    }

    /**
     * 不知道是什么异常,但如果是受检异常则处理完不抛出（IO异常），如果是不受检异常（NPP异常）则重新抛出
     * throwIfUnchecked()
     * Throwable类型为Error或RuntimeException才抛出 (不受检异常),NPP是运行期异常，所以会抛出
     */
    public static void c(){
        try {
            throw new NullPointerException();
        } catch (Throwable t) {
            // todo
            // 重新抛出
            Throwables.throwIfUnchecked(t);
        }
    }

    /**
     * 不知道是什么异常，但是处理完全部抛出！
     * throwIfUnchecked()
     * Throwable类型为Error或RuntimeException才抛出 () ,IO是受检异常，所以不会抛出
     * 那么,受检异常则可以直接throw  ,也可以用RuntimeException包装下抛出
     * 为了不影响调用放心，建议使用RuntimeException包装下抛出!
     */
    public static void d() {
        try {
            throw new IOException();
        } catch (Throwable t) {
            // todo
            //重新抛出
            Throwables.throwIfUnchecked(t);
            throw new RuntimeException(t);
        }
    }


    /**
     *  研究异常的三个方法
     */
    public static void e(){
        try {
            throw new IOException();
        } catch (Throwable t) {
            String string = Throwables.getStackTraceAsString(t);
            Throwable throwable =  Throwables.getRootCause(t);
            List<Throwable> list = Throwables.getCausalChain(t);

            System.out.println(string);
            System.out.println(throwable.toString());
            System.out.println(list.get(0));
        }
    }

    public static void main(String[] args){
        // a();
        // b();
        // c();
        e();
    }
}
