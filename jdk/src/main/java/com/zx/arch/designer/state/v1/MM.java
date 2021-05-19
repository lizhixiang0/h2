package com.zx.arch.designer.state.v1;

import lombok.AllArgsConstructor;

/**
 * 定义小女孩的两种状态
 * @author admin
 */
enum MMState {HAPPY, SAD}

/**
 * 使用switch 或者 if...else.. 来让小女孩在不同的状态下做出对应的行为
 * 如果想再加一种状态.比如愤怒，需要改源代码
 * @author admin
 */
@AllArgsConstructor
public class MM {

    MMState state;

    public void smile() {
        switch (state) {
            case HAPPY:
                System.out.println("开心得笑");
                break;
            case SAD:
                System.out.println("悲伤的笑");
                break;
        }

    }

    public static void main(String[] args) {
        MM girl = new MM(MMState.HAPPY);
        girl.smile();
    }
}






