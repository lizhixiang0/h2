package com.zx.arch.nio.toUse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description  判断文件是否被占用
 **/
public class Test01 {
    public static void main(String[] args) throws IOException {

        new Thread(()->{
            Path of = Path.of("D:\\JetBrains\\workspace\\paxvas-app-scan-engine-v2\\engine\\python\\tools\\rules", "android_rules.yar");
            List<String> list = null;
            try {
                list = Files.readAllLines(of);
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println(list);
        }).start();
    }
}
