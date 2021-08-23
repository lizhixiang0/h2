package com.zx.arch.io.core.toUse;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class FileTest {

    public static void reFileName() throws IOException {
        Path path1 = Paths.get("D:\\workspace\\h2\\jdk\\src\\main\\java\\com\\zx\\arch\\io\\core\\toUse", "sss");
        File file = path1.toFile();
        System.out.println(file.exists());
        Files.write(path1, "ss".getBytes(),StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
    }

    public static void main(String[] args) throws IOException {
        reFileName();
    }

}
