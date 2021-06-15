package com.zx.arch.designer.bridge.v1;


/**
 * GiftImpl可以定义成接口或者抽象类，但是Gift只能定义成abstract类，因为它里面需要聚合GiftImpl
 */
public abstract class  GiftImpl {
}

class Book extends GiftImpl {
}

class Flower extends GiftImpl{}


