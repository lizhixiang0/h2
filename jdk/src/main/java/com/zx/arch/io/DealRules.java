package com.zx.arch.io;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.FactoryBeanNotInitializedException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author lizx
 * @since 1.0.0
 * @description 处理规则文件,将没有描述的规则剔除掉
 **/
public class DealRules {
    static Path src  = Path.of("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\resources\\static\\use\\android_rules.yar");
    static Path dest  =  Path.of("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\resources\\static\\rulesets\\android_rules.yar");
    static Path not  =  Path.of("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\resources\\static\\rulesets\\not_rules.yar");

    /**
     * 大括号移位、去除_a
     * @throws IOException
     */
    public static void move() throws IOException {
        Stream<String> stream = Files.readAllLines(src).stream();
        stream.forEach(i-> {
            try {
                if(i.trim().startsWith("rule")&&i.trim().endsWith("{")){
                    i=i.replace("{","\r\n{");
                }
                if(i.trim().startsWith("rule")&&i.contains("_a")){
                    i = i.replace("_a","");
                }
                Files.writeString(dest,i.concat("\r\n"),StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    /**
     * 以##为界限进行split ,那就得先把干扰的空格全去除，然后再在每个规则前面加"##\r\n"
     */
    public static void deleteBlank() throws IOException {
        Stream<String> stream = Files.readAllLines(src).stream();

        stream.filter(StringUtils::isNotBlank).forEach(i-> {
            try {
                if(i.trim().startsWith("rule")){
                    i = i.replaceAll("rule","##\r\nrule");
                }
                Files.writeString(dest,i.concat("\r\n"),StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    /**
     * 以"\r\n"为界限进行split,把没有description的放到另一个文件里
     * @param args
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        Stream<String> stream = Files.readAllLines(src).stream();
        String content = stream.collect(Collectors.joining("\r\n"));
        String[] arr = content.split("##");
        for(String i:arr){
            if(i.contains("description")){
                Files.writeString(dest,i,StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }else{
                Files.writeString(not,i,StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }
        }

    }






}
