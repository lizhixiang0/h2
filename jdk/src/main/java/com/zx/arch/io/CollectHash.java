package com.zx.arch.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author lizx
 * @since 1.0.0
 * @description 从文件中获取类型为android的MD5码值，并写入到指定文件  ，约束：文件中每一个item单独占一行
 **/
public class CollectHash {
    public static void collectHash() throws IOException {
        Path source = Path.of("C:\\Users\\admin\\Downloads\\APT_Digital_Weapon-master");
        File f = source.toFile();
        if(f.isDirectory()){
            // 拿到第一个文件夹
            File a = Objects.requireNonNull(f.listFiles())[0];
            if(a.isDirectory()){
                // 拿到第一个文件夹中的所有文件
                File[] son =a.listFiles();
                assert son != null;
                Stream<String> stream = Files.lines(Path.of(String.valueOf(son[1])));
                Path dest  = Path.of("C:\\Users\\admin\\PycharmProjects\\pythonProject\\test.report");
                String s = stream.filter(Objects::nonNull).map(Objects::toString).filter(g->g.contains("Android")).map(i->i.substring(2,34)).map(Object::toString).collect(Collectors.joining(","));;
                Files.write(dest,s.getBytes());
            }
        }
    }

    public static void main(String[] args) throws IOException {
        collectHash();
    }
}
