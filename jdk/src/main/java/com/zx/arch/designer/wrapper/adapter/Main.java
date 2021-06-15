package com.zx.arch.designer.wrapper.adapter;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;

/**
 * @description 适配器模式的核心在于适配器，给每个原始类配置各自的适配器类,这个适配器会实现统一的接口，这样就做到了规范化！
 *              如果以后需要根据不同情况使用不同的对象（不同的对象方法不一样，不然可以直接使用策略模式），则可以使用这个模式。
 *              例如spring中根据映射找不同的controller ,例如写appscan是根据identity找不同的引擎，都可以使用这个模式。
 *              https://www.cnblogs.com/tongkey/p/7919401.html
 *
 *              可以参考mybatis中的日志模块。
 *
 * @link   "https://blog.csdn.net/wwwdc1012/article/details/82780560
 *        通常会有一个适配类，核心作用在于将一个类转化成另一个，转化的同时改变原方法。最后的表现形式为改变了接口
 *        方式比较多,可以通过继承或者组合。
 *        通常一个原类对应一个adapter,说到底就是包装器！
 *        spring中包含adapter名字类，实际就是 || new 包装对象 （被包装对象） ||,然后在包装对象内部进行处理，是采用组合还是彻底的转化，看具体业务。
 *
 */
public class Main {
    public static void main(String[] args) throws Exception {
        FileInputStream fis = new FileInputStream("c:/test.text");
        // 这里用的适配器模式,使得InputStream接口转变成Reader接口,然后才可以使用BufferedReader
        // 说到底就是将InputStream转变成另外一个对象了,但是感知不到.
        InputStreamReader isr = new InputStreamReader(fis);
        BufferedReader br = new BufferedReader(isr);
        String line = br.readLine();
        while (line != null && !line.equals("")) {
            System.out.println(line);
        }
        br.close();


    }
}
