package com.zx.arch.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * @author lizx
 * @since 1.0.0
 * @description 将rules文件分割
 **/
public class RuleSpliter {

    public static void main(String[] args) throws IOException {
        spliter();
    }

    private static void spliter() throws IOException {
        Path srcPath = Path.of("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\resources\\static\\android_rules.yar");
        Path destPath = Path.of("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\resources\\static\\small_rules.yar");
        Stream<String> stream =  Files.lines(srcPath);
        AtomicInteger count = new AtomicInteger();
        stream.forEach(
                i->{
                    try {
                        if(count.get()<1500)
                        Files.writeString(destPath,i.concat("\r\n"), StandardOpenOption.CREATE,StandardOpenOption.APPEND);
                        count.getAndIncrement();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
        );
    }
}


