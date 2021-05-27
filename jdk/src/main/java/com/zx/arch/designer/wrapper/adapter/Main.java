package com.zx.arch.designer.wrapper.adapter;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;

/**
 * @description 适配器模式的用意是要改变原有的接口，以便于适应目标接口。
 * @link   "https://blog.csdn.net/wwwdc1012/article/details/82780560
 *        通常会有一个适配类，核心作用在于将一个类转化成另一个，转化的同时改变原方法。最后的表现形式为改变了接口
 *        方式比较多,可以通过继承或者组合
 */
public class Main {
    public static void main(String[] args) throws Exception {
        FileInputStream fis = new FileInputStream("c:/test.text");
        // 这里用的适配器模式,使得InputStream接口转变成Reader接口,然后才可以使用BufferedReader
        InputStreamReader isr = new InputStreamReader(fis);
        BufferedReader br = new BufferedReader(isr);
        String line = br.readLine();
        while (line != null && !line.equals("")) {
            System.out.println(line);
        }
        br.close();


    }
}
