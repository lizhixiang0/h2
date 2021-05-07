package com.zx.arch.designer.strategy.v2;

import java.util.Arrays;

/**
 * 2、修改排序器,使得能够对猫的重量进行排序
 * @author lizx
 * @since 1.0.0
 **/
class Sorter{

    public void sort(Cat[] arr) {
        for(int i=0; i<arr.length - 1; i++) {
            int minPos = i;
            for(int j=i+1; j<arr.length; j++) {
                minPos = arr[j].compareTo(arr[minPos])==-1?j:minPos;
            }
            swap(arr, i, minPos);
        }
    }

    void swap(Cat[] arr, int i, int j) {
        Cat temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

public class Main {
    public static void main(String[] args) {
        Cat[] a = {new Cat(3, 3), new Cat(5, 5), new Cat(1, 1)};
        Sorter sorter = new Sorter();
        sorter.sort(a);
        System.out.println(Arrays.toString(a));
    }
}
