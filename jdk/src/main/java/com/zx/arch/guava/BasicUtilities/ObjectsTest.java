package com.zx.arch.guava.BasicUtilities;


import com.google.common.base.Objects;
import lombok.Data;

/**
 * @author lizx
 * @since 1.0.0
 * @description   常见的Object方法改写
 * @blog          "http://ifeve.com/google-guava-commonobjectutilities/"
 **/
@Data
public class ObjectsTest implements Comparable<ObjectsTest>{
    // 测试ComparisonChain
    private String name;
    private int age;

    /**
     * 1、Objects.equal()  避免元素为null报错
     */
    private static void a(){
        // returns false
        Objects.equal(null, "a");
    }

    /**
     * 计算hashcode更加方便
     */
    private static void b(){
        Integer temp1 = Objects.hashCode(null,2,3,4,5);
        //注意：JDK7引入的Objects类提供了一样的方法Objects.hash(Object...)
        Integer temp2 = java.util.Objects.hash(null,2,3,4,5);
        //两者其实都是调用的Arrays.hashCode(values)
        System.out.println(Objects.equal(temp1,temp2));
    }

    @Override
    public int compareTo(ObjectsTest o) {
        return 0;
    }

    public static void main(String[] args) {
        
    }

}
