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
 * @description ������Ŀ��Դ
 * @note ��Դ����static��֮��Ҫ������,ClassPathResource���ص�����·���µ���Դ
 **/
@Log
public class LoadResource {
    private static final String IMAGE_PATH_FORMAT = "static/%s.png";
    private static final String IMAGE_NAME = "android";
    private static String path;
    static {
        path = String.format(IMAGE_PATH_FORMAT, IMAGE_NAME);
    }

    /**
     * ��ȡͼƬ��Դ
     * @throws IOException
     */
    private static void getImage() throws IOException, URISyntaxException {
        /**
         * Spring��ClassPathResource��
         */

        Resource imageRes = new ClassPathResource(path);
        log.info(String.valueOf(imageRes.getURI()));


        /**
         * ��jdk
         * ClassLoader  ͨ��ClassUtils���Ӧ�ü����� ��AppClassLoader
         */
        ClassLoader classLoader = ClassUtils.getDefaultClassLoader();
        URL images = classLoader.getResource(path);
        log.info(String.valueOf(images.toURI()));
    }

    public static void main(String[] args) throws IOException, URISyntaxException {
        getImage();
    }
}
