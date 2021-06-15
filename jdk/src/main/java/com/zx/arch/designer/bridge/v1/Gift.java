package com.zx.arch.designer.bridge.v1;

/**
 * 这个类只能定义成抽象类，因为里面需要聚合一个GiftImpl
 */
public abstract class Gift {
    /**
     * gift抽象性质里面聚合一个gift真实实现
     */
    GiftImpl impl;
}

/**
 * 温暖的礼物
 */
class WarmGift extends Gift {
    public WarmGift(GiftImpl impl) {
        this.impl = impl;
    }
}

/**
 * 狂野的礼物
 */
class WildGift extends Gift {
    public WildGift(GiftImpl impl) {
        this.impl = impl;
    }
}




