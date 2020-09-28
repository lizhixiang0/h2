package com.zx.arch.review.list;

import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

/**
 * @author lizx
 * @since 1.0.0
 * @description 不能在for循环里进行remove/add 操作,如果需要则使用Iterator
 * @blog " https://www.cnblogs.com/liyong888/p/7799272.html
 **/
public class TraverseListTest {
    private static ArrayList<String> list = Lists.newArrayList();

    static {
        list.add("a");
        list.add("b");
        // 只有两个元素执行remove会报错!三个元素则不会,具体原因和for循环内部的迭代器有关系!
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
     * list 的remove()方法里用到System.arraycopy() ,了解下他的作用
     */
    public static void b(){
        int[] src = {1,2,3,4};
        int[] dest = new int[3];

        // 这个方法一共五个参数
        // 第一个参数是原数组!第三个参数是目标数组
        // 意思是将原数组从下标为1开始,复制2个值到目标数组!目标数组从下标0开始!
        // 注意复制过去的值数量不能超过目标数组大小
        System.arraycopy(src,1,dest,0,2);

        System.out.println(Arrays.toString(dest));
    }
    public static void main(String[] args) {
        // 如果需要一边循环一边处理(remove/add)集合中的元素，使用iterator,不要使用for循环
       c();
    }

}
