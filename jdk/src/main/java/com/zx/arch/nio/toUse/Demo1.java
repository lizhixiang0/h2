package com.zx.arch.nio.toUse;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @description 简单使用下nio
 **/
public class Demo1 {
    /**
     * 利用Files来读取文件
     * @throws URISyntaxException
     * @throws IOException
     */
    private static void a() throws URISyntaxException, IOException {
        List<String> content = Files.readAllLines(Paths.get(Demo1.class.getResource("/static/test.txt").toURI()), StandardCharsets.UTF_8 );
        System.out.println(content);
    }

    public static void main(String[] args) throws IOException, URISyntaxException {
        a();
    }
}
