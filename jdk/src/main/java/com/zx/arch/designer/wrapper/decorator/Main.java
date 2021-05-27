package com.zx.arch.designer.wrapper.decorator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;

/**
 * @description 装饰器模式的作用就是在不改变其结构的情况下赋予被装饰的类更多功能
 *              其实核心就是使用组合关系来实现继承的效果，网上很多资料又将这种方式称为对象型适配器模式 ！ ！！
 * @link        "http://c.biancheng.net/view/1366.html
 */
public class Main {
    public static void main(String[] args) throws Exception {
        File f = new File("c:/work/test.data");
        FileOutputStream fos = new FileOutputStream(f);
        OutputStreamWriter osw = new OutputStreamWriter(fos);
        // 这里用的装饰模式,增强功能
        BufferedWriter bw = new BufferedWriter(osw);
        bw.write("http://www.mashibing.com");
        bw.flush();
        bw.close();
    }
}
