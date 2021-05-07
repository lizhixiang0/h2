package com.zx.arch.designer.strategy.v3;

import java.util.Arrays;

/**
 * 3、修改排序器,使得能对所有对象进行排序，例如对狗进行排序
 * 这里我们会想到将Cat换成Object,但是Object类型没有compareTo方法,所以应该是换成Comparable类型
 * @author lizx
 * @since 1.0.0
 **/
class Sorter{

    public void sort(Comparable[] arr) {
        for(int i=0; i<arr.length - 1; i++) {
            int minPos = i;
            for(int j=i+1; j<arr.length; j++) {
                minPos = arr[j].compareTo(arr[minPos])==-1?j:minPos;
            }
            swap(arr, i, minPos);
        }
    }

    void swap(Comparable[] arr, int i, int j) {
        Comparable temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

/**
 * @author admin
 */
public class Main {
    public static void main(String[] args) {
        Dog[] a = {new Dog(3), new Dog(5), new Dog(1)};
        Sorter sorter = new Sorter();
        sorter.sort(a);
        System.out.println(Arrays.toString(a));
    }
}
