package com.zx.arch.io;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * @author lizx
 * @since 1.0.0
 * @description  使用IO流的过程中产生的一些疑问，在此验证
 **/
public class IOTest {


    /**
     * 我为啥要写这个方法，我一直以为只提供文件夹的URL拿到的InputStream和子文件夹没有关系，原来不是
     * 原来可以逐行读取到子文件的名字？所以我怀疑文件夹也是一个文件，然后它的每行都是子文件的名字？？
     * 正解！
     * 操蛋了。。。
     */
    private static void aVoid() throws IOException, URISyntaxException {
        URL url = ClassLoader.getSystemClassLoader().getResource("static/IOTest").toURI().toURL();
        InputStream is = url.openStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        for (String line; (line = reader.readLine() )!= null;) {
            System.out.println(line);
        }
    }

    public static void main(String[] args) throws IOException, URISyntaxException {
        aVoid();
    }

}
