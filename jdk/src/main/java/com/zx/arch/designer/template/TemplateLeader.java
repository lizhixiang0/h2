package com.zx.arch.designer.template;

import com.google.common.collect.Lists;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description 定义一个操作中的算法骨架，而将算法的一些步骤延迟到子类中，使得子类可以不改变该算法结构的情况下重定义该算法的某些特定步骤。
 * @note   回调方法、模板方法模式、钩子（hook）区分 :"https://blog.csdn.net/Walk_er/article/details/74942366
 *         模板方法模式和建造者模式的区分 ：https://blog.csdn.net/ljianhui/article/details/8395492
 *                                       https://blog.csdn.net/ljianhui/article/details/8280594;
 *                                       模板方法模式是建造者者模式有一定的相似性。
 *
 *                                       都用到了个钩子函数,但建造者模式中使用的是组合的方式，而模板方法模式采用的是继承的方式
 *
 *          注：父类编写结构代码 (使用final)，子类实现实现细节(实现abstract方法)
 *              很多filter认证是这么搞的！
 *
 *              模板方法模式主要是利用继承！子类实现父类的抽象方法！父类编写共有方法！
 *
 *
 *
 **/
public class TemplateLeader {
    /**
     * 模板方法模式进化链
     */
    static List develop = Lists.newArrayList();

    /**
     * study log
     */
    static void setBasicLogs() {
        develop.add("基本上写代码这个模式是必定用得到的。");
        develop.add("在使用Spring Security时就用到了这个模式");
    }
}
