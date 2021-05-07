package com.zx.arch.designer.strategy.v2;

import lombok.ToString;

/**
 * @author admin
 */
@ToString
public class Cat implements Comparable<Cat> {
    public int weight, height;

    public Cat(int weight, int height) {
        this.weight = weight;
        this.height = height;
    }

    @Override
    public int compareTo(Cat c) {
        /*这里多说一嘴,得亏Comparable接口使用了泛型（如果不用泛型，那这里就是Object）,不然这里还得进行强制转换*/
        if(this.weight < c.weight) {
            return -1;
        } else if(this.weight > c.weight) {
            return 1;
        } else {
            return 0;
        }
    }
}
