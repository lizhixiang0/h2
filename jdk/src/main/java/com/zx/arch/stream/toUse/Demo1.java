package com.zx.arch.stream.toUse;

import com.sun.xml.internal.bind.api.impl.NameConverter;
import org.apache.tomcat.util.digester.DocumentProperties;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @decsription 如何创建、使用、关闭stream流
 **/
public class Demo1 {
    /**
     *
     */
    private  static  void createStream() throws IOException, URISyntaxException {
        List<String> content =Files.readAllLines(Paths.get(Demo1.class.getResource("/static/test.txt").toURI()),StandardCharsets.UTF_8 );
        System.out.println(content);
    }

    public static void main(String[] args) throws IOException, URISyntaxException {
        createStream();
    }

}
