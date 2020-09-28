package com.zx.arch.guava.BasicUtilities;

import com.google.common.base.MoreObjects;
import com.google.common.collect.Lists;
import com.google.common.collect.Ordering;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

/**
 * @author lizx
 * @since 1.0.0
 * @blog  "http://ifeve.com/google-guava-ordering/"
 * @note  guava 先创建排序器,然后可以调用相应的方法使用组合排序器！功能比原生的方法要丰富很多，最关键是还不用修改自定义类的代码！
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
     * 使用原生jdk对自定义类集合进行排序,一般没问题,但是如果出现null,则很恶心
     */
    private static void a(){
        /**
        *  1、如果自定义类已经实现了Comparable则直接排序
         *
        */
        Collections.sort(list1);
        System.out.println(list1.get(0).getAge());

        /**
         * 2、如果没有实现排序规则则使用排序器
         * 升序排的话就是第一个参数.compareTo(第二个参数);
         * 降序排的话就是第二个参数.compareTo(第一个参数);
         */
        Collections.sort(list2, (o1, o2) -> o2.getAge().compareTo(o1.getAge()));
        System.out.println(list2.get(0).getAge());

        /*
        * 3、JDK8之后提供了Stream操作，也支持排序
            https://blog.csdn.net/l1028386804/article/details/56513205
        * */
    }

    /**
     * 使用guava的排序,允许出现null情况,但是如果是采用自定义的排序规则，还是很难不好出现null 的情况
     */
    private static void b(){
        // https://blog.csdn.net/windrui/article/details/51558518
        // 有三种方法来创建排序器
        Ordering<PeopleTwo> orderingByNatural = Ordering.natural().nullsFirst().onResultOf(people -> people.getAge());
        Ordering<PeopleTwo> orderingByString = Ordering.usingToString().nullsFirst().onResultOf(people -> people.toString());
        Ordering<PeopleTwo> orderingByCustom = Ordering.from(Comparator.comparingInt(PeopleTwo::getAge));

        for (PeopleTwo p : orderingByNatural.sortedCopy(list2)) {
            System.out.println(MoreObjects.toStringHelper(p)
                    .add("name", p.getName())
                    .add("age", p.getAge())
            );
        }
    }


    public static void main(String[] args) {
        a();
    }
}

@Data
@AllArgsConstructor
class PeopleOne implements Comparable<PeopleOne>{
    private String name;
    private Integer age;

    @Override
    public int compareTo(PeopleOne o) {
        // 按照年龄大小降序排列
        // 这里注意JDK7之后要考虑相等的情况!,即不可以出现 return this.age > o.getAge()?-1:1 ; 这种写法!
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



