package com.zx.arch.io.core.toUse;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.Reader;

/**
 * @author lizx
 * @since 1.0.0
 * @description 马士兵的IO流讲解
 * @note
 *      1、IO的输入和输出是相对于程序而言，而不是资源（文件）
 *      2、IO分为节点流和处理流,其中处理流是节点流的包装器
 *      3、字节流一次读一个字节，字符流一次读2个字节 ？？
 **/
public class Demo01 {

    public static void a() throws FileNotFoundException {
        Reader reader = new FileReader("");
    }
}
