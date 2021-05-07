package com.zx.arch.designer.strategy.v4;

import com.zx.arch.designer.strategy.v2.Cat;

import java.util.Comparator;

/**
 * 比重量
 * @author admin
 */
public class CatWeightComparator implements Comparator<Cat> {
    @Override
    public int compare(Cat o1, Cat o2) {
        if(o1.weight < o2.weight) {
            return -1;
        } else if (o1.weight > o2.weight) {
            return 1;
        } else {
            return 0;
        }
    }
}
