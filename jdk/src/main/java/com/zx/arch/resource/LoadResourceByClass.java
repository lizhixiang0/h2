package com.zx.arch.resource;

import com.zx.arch.review.EnumTest;

import java.net.URISyntaxException;

/**
 * @author lizx
 * @since 1.0.0
 * @description 通过当前类加载项目资源
 * @note 使用class加载path 路径最好以"/"开头,这样会到类路径的根路径下去找,通常情况下我们会把资源放在resource文件下 ！resource经过编译会跑到根路径下
 *        如果不以"/"开头，会默认到所用的class所在包下面找,基本找不到。
 **/
public class LoadResourceByClass {
    private static final String IMAGE_PATH_FORMAT = "/static/%s.png";
    private static final String IMAGE_NAME = "android";
    private static String path;
    static {
        path = String.format(IMAGE_PATH_FORMAT, IMAGE_NAME);
    }

    private static void getImage() {

        System.out.println(LoadResourceByClass.class.getResource(path).getPath());
        System.out.println(EnumTest.class.getResource("").getPath());
        System.out.println(LoadResourceByClass.class.getResource("/").getPath());

        ///D:/JetBrains/workspace/h2/jdk/target/classes/static/android.png
        ///D:/JetBrains/workspace/h2/jdk/target/classes/com/zx/arch/resource/
        ///D:/JetBrains/workspace/h2/jdk/target/classes/
    }

    public static void main(String[] args) {
        getImage();
        //综上所述，使用class加载资源,path的首字母必须加上 "/"
    }
}
