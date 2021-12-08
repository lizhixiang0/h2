package com.zx.arch.designer;

import com.google.common.collect.Maps;
import com.zx.arch.designer.bridge.BridgeLeader;
import com.zx.arch.designer.builder.BuilderLeader;
import com.zx.arch.designer.chain.ChainLeader;
import com.zx.arch.designer.observer.ObserverLeader;
import com.zx.arch.designer.state.StateLeader;
import com.zx.arch.designer.strategy.StrategyLeader;
import com.zx.arch.designer.template.TemplateLeader;
import com.zx.arch.designer.wrapper.WrapperLeader;

import java.util.HashMap;

/**
 * @author lizx
 * @since 1.0.0
 * @description  设计模式理解------ 设计模式通常都是组合起来用的
 *
 * @link "https://www.bilibili.com/video/BV1RC4y1H7ok
 *        "http://c.biancheng.net/view/1378.html
 *
 *        https://www.bilibili.com/video/BV1mc411h719?p=6
 *        https://www.cnblogs.com/cbf4life/tag/%E8%AE%BE%E8%AE%A1%E6%A8%A1%E5%BC%8F/
 *
 * @ java语言使用设计模式常用用法;https://mp.weixin.qq.com/s/1yxPeAgqaHlWL7FJvoX9xQ
 **/
public class Leader {
    /**
     * 设计模式目录
     */
    static HashMap To_Analysis_Designer_logs = Maps.newHashMap();

    /**
     * 二、核心分析   https://blog.csdn.net/qq_29994609/article/details/51914046
     * study log
     */
    static void setBasicLogs() {
        // 1、行为型,主要解决类或者对象直接互相通信的问题，共11个
        To_Analysis_Designer_logs.put("观察者模式√", ObserverLeader.class);
        To_Analysis_Designer_logs.put("策略模式√", StrategyLeader.class);
        To_Analysis_Designer_logs.put("责任链模式", ChainLeader.class);
        To_Analysis_Designer_logs.put("状态模式", StateLeader.class);

        To_Analysis_Designer_logs.put("模板方法模式", TemplateLeader.class);
        To_Analysis_Designer_logs.put("代理模式", com.zx.arch.proxy.Leader.class);
        To_Analysis_Designer_logs.put("委派模式", "https://mp.weixin.qq.com/s/vDxsP9Vae32cGEod_TOt8A");

        // 2、结构性型,主要用于将类或对象进行组合从而构建灵活而高效的结构,共7个
        To_Analysis_Designer_logs.put("包装模式", WrapperLeader.class);
        To_Analysis_Designer_logs.put("桥接模式", BridgeLeader.class);
        To_Analysis_Designer_logs.put("门面模式", "https://mp.weixin.qq.com/s/Vyl9SHHyOb0fow7ZHk_4nw");

        // 3、创建型,主要解决如何灵活创建对象或者类的问题,共5个
        To_Analysis_Designer_logs.put("建造者模式", BuilderLeader.class);
    }

    /**
     * 七大原则
     */
    static void setAnalysisLogs() {
        /*
        * 1、最重要的原则就是单一原则,小到方法，大到一个类,都必须遵守这个原则。
        * */

    }
}
