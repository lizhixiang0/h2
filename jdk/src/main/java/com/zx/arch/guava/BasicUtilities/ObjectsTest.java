package com.zx.arch.guava.BasicUtilities;

import com.google.common.base.Objects;

/**
 * @author lizx
 * @since 1.0.0
 * @description   ������Object������д
 * @blog          "http://ifeve.com/google-guava-commonobjectutilities/"
 **/
public class ObjectsTest {
    /**
     * 1��Objects.equal()  ����Ԫ��Ϊnull����
     */
    private static void a(){
        // returns false
        Objects.equal(null, "a");
    }

    /**
     * �ö���������ֶ���ɢ��[hash]����Ӧ������
     */
    private static void b(){

    }

    public static void main(String[] args) {
        int id = 1;
        int timestamp = 100;
        int hash = 5;
        int hash1 = 67 * hash + (id ^ (id >>> 32));
        int hash2 = 67 * hash + (timestamp ^ (timestamp >>> 32));

        System.out.println(hash2);
        System.out.println(hash1);
    }
}
