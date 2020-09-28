package com.zx.arch.review.list;

import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

/**
 * @author lizx
 * @since 1.0.0
 * @description ������forѭ�������remove/add ����,�����Ҫ��ʹ��Iterator
 * @blog " https://www.cnblogs.com/liyong888/p/7799272.html
 **/
public class TraverseListTest {
    private static ArrayList<String> list = Lists.newArrayList();

    static {
        list.add("a");
        list.add("b");
        // ֻ������Ԫ��ִ��remove�ᱨ��!����Ԫ���򲻻�,����ԭ���forѭ���ڲ��ĵ������й�ϵ!
        //list.add("c");
    }

    private static void a(){
        for (String string:list) {
            if(StringUtils.equals("b",string)){
                list.remove(string);
            }
        }
    }

    private static void c(){
        Iterator<String> iterator = list.iterator();
        while(iterator.hasNext()){
            String string = iterator.next();
            if(StringUtils.equals("b",string)){
                iterator.remove();
            }
        }
    }

    /**
     * list ��remove()�������õ�System.arraycopy() ,�˽�����������
     */
    public static void b(){
        int[] src = {1,2,3,4};
        int[] dest = new int[3];

        // �������һ���������
        // ��һ��������ԭ����!������������Ŀ������
        // ��˼�ǽ�ԭ������±�Ϊ1��ʼ,����2��ֵ��Ŀ������!Ŀ��������±�0��ʼ!
        // ע�⸴�ƹ�ȥ��ֵ�������ܳ���Ŀ�������С
        System.arraycopy(src,1,dest,0,2);

        System.out.println(Arrays.toString(dest));
    }
    public static void main(String[] args) {
        // �����Ҫһ��ѭ��һ�ߴ���(remove/add)�����е�Ԫ�أ�ʹ��iterator,��Ҫʹ��forѭ��
       c();
    }

}
