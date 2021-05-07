package com.zx.arch.designer.strategy.v1;

import java.util.Arrays;

/**
 * 1、写一个排序器,对int数组进行排序
 * @author lizx
 * @since 1.0.0
 **/
class Sorter{
    public void sort(int[] arr) {
        for(int i=0; i<arr.length - 1; i++) {
            int minPos = i;

            for(int j=i+1; j<arr.length; j++) {
                minPos = arr[j]<arr[minPos]?j:minPos;
            }
            swap(arr, i, minPos);
        }
    }

    static void swap(int[] arr, int i, int j) {
        int temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

public class Main {
    public static void main(String[] args) {
        int[] a = {9, 2, 3, 5, 7, 1, 4};
        Sorter sorter = new Sorter();
        sorter.sort(a);
        System.out.println(Arrays.toString(a));
    }
}

