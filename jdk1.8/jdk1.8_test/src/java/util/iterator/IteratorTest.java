package util.iterator;

import java.util.Iterator;
import java.util.LinkedList;

/**
 * @author lizx
 * @date 2021/8/17
 * @description  ������Ϊʲô��ôţ�ƣ�Ϊʲô����������ı����ٶȼ����������飿��
 *               ������������ı����ٶȶ���һ����On ,����ֻ���� ����Ͳ�ѯ��һ����
 * @blog "https://blog.csdn.net/longshengguoji/article/details/41551491
 * @since
 **/
public class IteratorTest {
    public static void main(String[] args) {
        LinkedList linkedList = new LinkedList();
        linkedList.add(1);
        Iterator iterator = linkedList.iterator();
        while (iterator.hasNext()){
            iterator.next();
        }
    }
}
