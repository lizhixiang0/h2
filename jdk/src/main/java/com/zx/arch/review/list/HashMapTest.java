package com.zx.arch.review.list;

import com.google.common.collect.Maps;
import org.checkerframework.checker.units.qual.K;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author lizx
 * @since 1.0.0
 * @description ʹ��HashMap��ע���
 **/
public class HashMapTest {
    private static HashMap map = new HashMap(16);

    static {
        map.put(1,"a");
        map.put(2,"b");
    }

    /**
     * 1��ʹ��EntrySet����
     */
    public static void a(){
        Set<Map.Entry> set=map.entrySet();
        for(Map.Entry entry:set){
            System.out.println(entry.getKey()+entry.getValue().toString());
        }
    }

    /**
     * 2��ʹ��keySet����
     */
    public static void b(){
        Set set= map.keySet();
        for(Object integer:set){
            System.out.println(integer+map.get(integer).toString());
        }
    }

    /**
     * 3��Map.foreach()
     */
    public static void c(){
        map.forEach((k,v)->{
            System.out.println(k+v.toString());
        });
    }

    public static void main(String[] args) {
        // ���������Ƽ�ʹ��EntrySet �������JDK8ʹ��forEach()
        c();
    }
}
