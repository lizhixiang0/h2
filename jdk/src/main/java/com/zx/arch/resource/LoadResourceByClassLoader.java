package com.zx.arch.resource;

import lombok.extern.java.Log;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.ClassUtils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;

/**
 * @author lizx
 * @since 1.0.0
 * @description ͨ���������������Ŀ��Դ
 * @note ��Դ����static��֮��Ҫ������,ClassPathResource���ص�����·���µ���Դ,
 *       ע��һ����������Դ������ͨ�������������static�ļ����������Դ��Ҫ��ǰ�����"/"
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
         * 1��Spring��ClassPathResource��
         */
        Resource imageRes = new ClassPathResource(path);
        log.info(String.valueOf(imageRes.getURI()));

        /**
         * 2����jdk
         * ͨ��ClassUtils���Ӧ�ü����� ��AppClassLoader
         */
        ClassLoader classLoader = ClassUtils.getDefaultClassLoader();
        URL images = classLoader.getResource(path);
        log.info(String.valueOf(images.toURI()));
    }

    /**
     * Ϊʲô���������ƾһ�������Ϳ����ҵ����ļ���
     * @blog "https://blog.csdn.net/u013412772/article/details/80837735
     */
    private static void classPath() throws IOException {
        String classPath = System.getProperty("java.class.path");
        for (String path : classPath.split(";")) {
            System.out.println(path);
        }

        ArrayList<URL> list = Collections.list(Thread.currentThread().getContextClassLoader().getResources("com/zx/arch"));
        list.forEach(i-> System.out.println(i.getPath()));

    }

    public static void main(String[] args) throws IOException, URISyntaxException {
        //getImage();
        //file:/D:/JetBrains/workspace/h2/jdk/target/classes/static/android.png
        classPath();
    }
}
