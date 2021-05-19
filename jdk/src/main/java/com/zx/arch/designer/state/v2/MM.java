package com.zx.arch.designer.state.v2;


import lombok.AllArgsConstructor;

/**
 * 将目标的状态和行为抽象出来
 */
abstract class MMState {
    abstract void smile();
    abstract void cry();
    abstract void say();
}

class MMHappyState extends MMState {
    @Override
    void smile() {
        System.out.println("happy smile");
    }
    @Override
    void cry() {}
    @Override
    void say() {}
}

class MMSadState extends MMState {
    @Override
    void smile() {
        System.out.println("sad smile");
    }
    @Override
    void cry() {}
    @Override
    void say() {}
}

/**
 * 需要增加新的状态时，直接增加一个状态类即可
 */
@AllArgsConstructor
public class MM {
    MMState state;

    public void smile() {
        state.smile();
    }

    public void cry() {
        state.cry();
    }

    public void say() {
        state.say();
    }

    public static void main(String[] args) {
        // 使用时传入状态对象,这里有点像策略模式
        // https://zhuanlan.zhihu.com/p/91912672
        MM girl = new MM(new MMHappyState());
        girl.smile();
    }

}


