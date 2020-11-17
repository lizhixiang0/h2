package com.zx.arch.guava.BasicUtilities;

import com.google.common.base.MoreObjects;
import com.google.common.collect.Lists;
import com.google.common.collect.Ordering;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.stream.Collectors;

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
        list2.add(new PeopleTwo("a",2));
        list2.add(new PeopleTwo("b",1));
        list2.add(new PeopleTwo("b",null));
        //list2.add(null);
    }
    /**
     * ʹ��ԭ��jdk���Զ����༯�Ͻ�������,һ��û����,�����������null,��ܶ���
     */
    private static void a(){
        /**
        *  1������Զ������Ѿ�ʵ����Comparable��ֱ������
         *
        */
        //Collections.sort(list1);
        //System.out.println(list1.get(0).getAge());

        /**
         * 2�����û��ʵ�����������ʹ��������,�����д��ʵ����ʵ����Comparator��lambdaд��
         * �����ŵĻ����ǵ�һ������.compareTo(�ڶ�������);
         * �����ŵĻ����ǵڶ�������.compareTo(��һ������);
         */
        //Collections.sort(list2, (o1, o2) -> o2.getAge().compareTo(o1.getAge()));
        //System.out.println(list2.get(0).getAge());

        /*
        * 3��JDK8֮���ṩ��Stream������Ҳ֧������
            "https://blog.csdn.net/l1028386804/article/details/56513205
        * */
        list2 = (ArrayList<PeopleTwo>) list2.stream().sorted(Comparator.comparing(PeopleTwo::getAge)
                .thenComparing(PeopleTwo::getName).reversed()).collect(Collectors.toList());
        System.out.println(list2.get(0).getAge());
    }

    /**
     * ʹ��guava������,�������null���,��������ǲ����Զ����������򣬻��ǲ��ð��ճ���null �����
     */
    private static void b(){
        // https://blog.csdn.net/windrui/article/details/51558518
        // �����ַ���������������
        Ordering<PeopleTwo> orderingByNatural = Ordering.natural().nullsFirst().onResultOf(PeopleTwo::getAge);
        Ordering<PeopleTwo> orderingByString = Ordering.usingToString().nullsFirst().onResultOf(PeopleTwo::getName);
        Ordering<PeopleTwo> orderingByCustom = Ordering.from(Comparator.comparingInt(PeopleTwo::getAge).thenComparing(PeopleTwo::getName));

        for (PeopleTwo p : orderingByCustom.sortedCopy(list2)) {
            System.out.println(MoreObjects.toStringHelper(p)
                    .add("name", p.getName())
                    .add("age", p.getAge())
            );
        }
    }


    public static void main(String[] args) {
        b();
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
        // ����ע��JDK7֮��Ҫ������ȵ����!,�������Գ��� return this.age > o.getAge()?-1:1 ; ����д��!
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



