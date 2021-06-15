package com.zx.arch.designer.bridge.v1;

public class GG {
    public void chase(MM mm) {
        // 真正创建礼物对象时,传入一个聚合类
        Gift g = new WarmGift(new Flower());
        give(mm, g);
    }

    public void give(MM mm, Gift g) {
        System.out.println(g + "gived!");
    }

}

class MM {
    String name;
}
