package util.list;


import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;

/**
 * @author lizx
 * @date 2021/8/17
 * @description  �ó����ۡ��Ժ�������鼯�ϻ��Ǿ���ʹ��forѭ������������������ʹ��forEach ��
 * @since
 **/
public class RandomAccessTest {
    public static void main(String[] args) {
        // ׼������
        ArrayList arrayList = new ArrayList();
        LinkedList linkedList = new LinkedList();
        for (int i = 0; i<50000; i++){
            arrayList.add(i);
            linkedList.add(i);
        }

        // ��������forѭ��ȡ��
        long startTime = System.currentTimeMillis();
        for (int i = 0; i <arrayList.size();i++){
            Object o = arrayList.get(i);
        }
        long endTime = System.currentTimeMillis();

        System.out.println(endTime-startTime);

        // ��������forEachѭ��ȡ��
        long startTime3 = System.currentTimeMillis();
        arrayList.forEach(i->{});
        long endTime3 = System.currentTimeMillis();

        System.out.println(endTime3-startTime3);

//        // ��������forѭ��ȡ��
//        long startTime1 = System.currentTimeMillis();
//        for (int i = 0; i <linkedList.size();i++){
//            Object o = linkedList.get(i);
//        }
//        long endTime1 = System.currentTimeMillis();
//        System.out.println(endTime1-startTime1);

        // ��������forEachȡ��
        long startTime2 = System.currentTimeMillis();
        Iterator iterator = linkedList.iterator();
        while (iterator.hasNext()){
            iterator.next();
        }
        //linkedList.forEach(i->{}); //forEach�Ǹ��﷨�ǣ�ʵ�ʾ���ʹ�õĵ�����
        long endTime2 = System.currentTimeMillis();

        System.out.println(endTime2-startTime2);
    }
}
