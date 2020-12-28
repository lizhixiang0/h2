package com.zx.arch.resource;

import lombok.extern.java.Log;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.ClassUtils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * @author lizx
 * @since 1.0.0
 * @description 通过类加载器加载项目资源
 * @note 资源放入static包之后要编译下,ClassPathResource加载的是类路径下的资源,
 *       注意一点和类加载资源的区别，通过类加载器加载static文件夹下面的资源不要在前面加上"/"
 **/
@Log
public class LoadResourceByClassLoader {
    private static final String IMAGE_PATH_FORMAT = "static/%s.png";
    private static final String IMAGE_NAME = "android";
    private static String path;
    static {
        path = String.format(IMAGE_PATH_FORMAT, IMAGE_NAME);
    }

    private static void getImage() throws IOException, URISyntaxException {
        /**
         * 1、Spring的ClassPathResource类
         */
        Resource imageRes = new ClassPathResource(path);
        log.info(String.valueOf(imageRes.getURI()));

        /**
         * 2、纯jdk
         * 通过ClassUtils获得应用加载类 即AppClassLoader
         */
        ClassLoader classLoader = ClassUtils.getDefaultClassLoader();
        URL images = classLoader.getResource(path);
        log.info(String.valueOf(images.toURI()));
    }

    public static void main(String[] args) throws IOException, URISyntaxException {
        getImage();
        //file:/D:/JetBrains/workspace/h2/jdk/target/classes/static/android.png
    }
}
