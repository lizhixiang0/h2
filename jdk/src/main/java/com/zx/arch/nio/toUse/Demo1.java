package com.zx.arch.nio.toUse;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.Callable;

/**
 * @author lizx
 * @since 1.0.0
 * @description 简单使用下nio
 **/
public class Demo1 {
    /**
     * 利用Files.readAllLines()来读取文件
     * @throws URISyntaxException
     * @throws IOException
     */
    private static void a() throws URISyntaxException, IOException {
        List<String> content = Files.readAllLines(Paths.get(Demo1.class.getResource("/static/test.txt").toURI()), StandardCharsets.UTF_8 );
        System.out.println(content);
    }

    /**
     * 使用scanner读取文件
     * @throws IOException
     */
    private static void b() throws IOException{
        Scanner scanner = new Scanner(Paths.get(Demo1.class.getResource("/static/test.txt").getPath().substring(1)), StandardCharsets.UTF_8);//
        while (scanner.hasNext()){
            System.out.println(scanner.nextLine());
        }
    }


    /**
     * 要改
     * @throws FileNotFoundException
     */
    private static void c() throws FileNotFoundException {
        PrintWriter printWriter = new PrintWriter(Path.of(Demo1.class.getResource("/static/test.txt").getPath().substring(1)).toString());
        printWriter.print("JJJJJJJJJ");
    }



    public static void main(String[] args) throws IOException, URISyntaxException {
        //可以通过System类找到java虚拟机启动目录的位置
        System.out.println(System.getProperties().get("user.dir"));
        c();
                a();

    }
}
