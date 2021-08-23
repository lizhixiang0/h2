package util.list;

import java.util.Iterator;
import java.util.LinkedList;

/**
 * @author lizx
 * @date 2021/8/17
 * @description  迭代器为什么这么牛逼？为什么他能让链表的遍历速度几乎赶上数组？？
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
