package util.list;


import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;

/**
 * @author lizx
 * @date 2021/8/17
 * @description  得出结论。以后遍历数组集合还是尽量使用for循环！如果是链表则必须使用forEach ！
 * @since
 **/
public class RandomAccessTest {
    public static void main(String[] args) {
        // 准备数据
        ArrayList arrayList = new ArrayList();
        LinkedList linkedList = new LinkedList();
        for (int i = 0; i<50000; i++){
            arrayList.add(i);
            linkedList.add(i);
        }

        // 测试数组for循环取数
        long startTime = System.currentTimeMillis();
        for (int i = 0; i <arrayList.size();i++){
            Object o = arrayList.get(i);
        }
        long endTime = System.currentTimeMillis();

        System.out.println(endTime-startTime);

        // 测试数组forEach循环取数
        long startTime3 = System.currentTimeMillis();
        arrayList.forEach(i->{});
        long endTime3 = System.currentTimeMillis();

        System.out.println(endTime3-startTime3);

//        // 测试链表for循环取数
//        long startTime1 = System.currentTimeMillis();
//        for (int i = 0; i <linkedList.size();i++){
//            Object o = linkedList.get(i);
//        }
//        long endTime1 = System.currentTimeMillis();
//        System.out.println(endTime1-startTime1);

        // 测试链表forEach取数
        long startTime2 = System.currentTimeMillis();
        Iterator iterator = linkedList.iterator();
        while (iterator.hasNext()){
            iterator.next();
        }
        //linkedList.forEach(i->{}); //forEach是个语法糖，实际就是使用的迭代器
        long endTime2 = System.currentTimeMillis();

        System.out.println(endTime2-startTime2);
    }
}
