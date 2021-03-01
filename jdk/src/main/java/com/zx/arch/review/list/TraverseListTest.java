package com.zx.arch.review.list;

import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

/**
 * @author lizx
 * @since 1.0.0
 * @description 如果使用增强for循环,在循环内部通过iterator增删元素
 *              如果使用普通for循环,那就直接操作list ,注意使用倒序遍历。有坑。
 *              总之，不能混用。
 * @blog " https://www.cnblogs.com/liyong888/p/7799272.html
 * @blog "https://zhuanlan.zhihu.com/p/353103151"
 **/
public class TraverseListTest {
    private static ArrayList<String> list = Lists.newArrayList();

    static {
        list.add("a");
        list.add("a");
        list.add("b");
        list.add("c");
    }

    private static void a(){
        for (int i =0;i<list.size();i++) {
            String string = list.get(i);
            if(StringUtils.equals("a", string)){
                list.remove(string);
            }
        }
        list.forEach(System.out::println);
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
       a();
    }

}
