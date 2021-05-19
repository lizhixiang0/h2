package com.zx.arch.designer.strategy.v4;


import com.zx.arch.designer.strategy.v2.Cat;

import java.util.Arrays;
import java.util.Comparator;


/**
 * 4、现在不想对猫的重量进行排序，想对高度进行排序,怎么办呢？
 *    修改排序器！,排序的时候传入一个比较器
 * @param <T>
 */
class Sorter<T> {

    public void sort(T[] arr, Comparator<T> comparator) {
        for(int i=0; i<arr.length - 1; i++) {
            int minPos = i;

            for(int j=i+1; j<arr.length; j++) {
                minPos = comparator.compare(arr[j],arr[minPos])==-1 ? j : minPos;
            }
            swap(arr, i, minPos);
        }
    }

    void swap(T[] arr, int i, int j) {
        T temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

public class Main {
    public static void main(String[] args) {
        Cat[] a = {new Cat(3, 3), new Cat(5, 5), new Cat(1, 1)};
        Sorter<Cat> sorter = new Sorter<>();
        sorter.sort(a,new CatHeightComparator());
        /*其实可以使用lambda表达式
        sorter.sort(a, (o1, o2)->{
            if(o1.weight < o2.weight) {
                return -1;
            } else if (o1.weight>o2.weight) {
                return 1;
            } else {
                return 0;
            }
        });
        */
        System.out.println(Arrays.toString(a));
    }
}
