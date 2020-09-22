package com.zx.arch.guava.BasicUtilities;


import com.google.common.base.Objects;
import lombok.Data;

/**
 * @author lizx
 * @since 1.0.0
 * @description   ������Object������д
 * @blog          "http://ifeve.com/google-guava-commonobjectutilities/"
 **/
@Data
public class ObjectsTest implements Comparable<ObjectsTest>{
    // ����ComparisonChain
    private String name;
    private int age;

    /**
     * 1��Objects.equal()  ����Ԫ��Ϊnull����
     */
    private static void a(){
        // returns false
        Objects.equal(null, "a");
    }

    /**
     * ����hashcode���ӷ���
     */
    private static void b(){
        Integer temp1 = Objects.hashCode(null,2,3,4,5);
        //ע�⣺JDK7�����Objects���ṩ��һ���ķ���Objects.hash(Object...)
        Integer temp2 = java.util.Objects.hash(null,2,3,4,5);
        //������ʵ���ǵ��õ�Arrays.hashCode(values)
        System.out.println(Objects.equal(temp1,temp2));
    }

    @Override
    public int compareTo(ObjectsTest o) {
        return 0;
    }

    public static void main(String[] args) {
        
    }

}
