package com.zx.arch.review.list;

import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

/**
 * @author lizx
 * @since 1.0.0
 * @description ���ʹ����ǿforѭ��,��ѭ���ڲ�ͨ��iterator��ɾԪ��
 *              ���ʹ����ͨforѭ��,�Ǿ�ֱ�Ӳ���list ,ע��ʹ�õ���������пӡ�
 *              ��֮�����ܻ��á�
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
       a();
    }

}
