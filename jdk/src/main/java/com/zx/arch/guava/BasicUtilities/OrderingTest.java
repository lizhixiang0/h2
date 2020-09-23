package com.zx.arch.guava.BasicUtilities;

import com.google.common.base.MoreObjects;
import com.google.common.collect.Lists;
import com.google.common.collect.Ordering;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.ArrayList;
import java.util.Collections;

/**
 * @author lizx
 * @since 1.0.0
 * @blog  "http://ifeve.com/google-guava-ordering/"
 * @note  guava �ȴ���������,Ȼ����Ե�����Ӧ�ķ���ʹ����������������ܱ�ԭ���ķ���Ҫ�ḻ�ܶ࣬��ؼ��ǻ������޸��Զ�����Ĵ��룡
 **/
public class OrderingTest {

    private static ArrayList<PeopleOne> list1 = Lists.newArrayList();
    private static ArrayList<PeopleTwo> list2 = Lists.newArrayList();
    static{
        list1.add(new PeopleOne("a",1));
        list1.add(new PeopleOne("b",2));
        list2.add(new PeopleTwo("a",1));
        list2.add(new PeopleTwo("b",2));
       // list2.add(new PeopleTwo("b",null));
    }
    /**
     * ʹ��ԭ��jdk���Զ����༯�Ͻ�������,һ��û����,�����������null,��ܶ���
     */
    private static void testEssentialMethod(){
        /**
        *  ����Զ������Ѿ�ʵ����Comparable��ֱ������
        */
        Collections.sort(list1);
        System.out.println(list1.get(0).getAge());

        /**
         * ���û��ʵ�����������ʹ��������
         * �����ŵĻ����ǵ�һ������.compareTo(�ڶ�������);
         * �����ŵĻ����ǵڶ�������.compareTo(��һ������);
         */
        Collections.sort(list2, (o1, o2) -> o2.getAge().compareTo(o1.getAge()));
        System.out.println(list2.get(0).getAge());
    }

    private static void testGuavaOrder(){
        // https://www.cnblogs.com/houzheng/p/10903403.html
        // https://blog.csdn.net/windrui/article/details/51558518
        Ordering<PeopleTwo> ordering = Ordering.natural().nullsFirst().onResultOf(people -> people.getAge());
        for (PeopleTwo p : ordering.sortedCopy(list2)) {
            System.out.println(MoreObjects.toStringHelper(p)
                    .add("name", p.getName())
                    .add("age", p.getAge())
            );
        }
    }


    public static void main(String[] args) {
        testEssentialMethod();
        testGuavaOrder();
    }
}

@Data
@AllArgsConstructor
class PeopleOne implements Comparable<PeopleOne>{
    private String name;
    private Integer age;

    @Override
    public int compareTo(PeopleOne o) {
        // ���������С��������
        if(this.age > o.getAge()) {
            return -1;
        }else if(this.age < o.getAge()) {
            return 1;
        }else{
            return 0;
        }
    }
}

@Data
@AllArgsConstructor
class PeopleTwo{
    private String name;
    private Integer age;
}



