package com.zx.arch.resource;

/**
 * @author lizx
 * @since 1.0.0
 * @description ͨ����ǰ�������Ŀ��Դ
 * @note ʹ��class����path ·�������"/"��ͷ,�����ᵽ��·���ĸ�·����ȥ��,ͨ����������ǻ����Դ����resource�ļ��� ������������ܵ���·����classes��
 *       �������"/"��ͷ����Ĭ�ϵ����õ�class�ļ���������ڰ�������,�����Ҳ�����
 *       ����������ǰ���Դ�ļ�����resource�������static�ļ����ô��ȡʱ�򻹱������"/static"
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
        System.out.println(LoadResourceByClass.class.getResource("").getPath());
        System.out.println(LoadResourceByClass.class.getResource("/").getPath());

        ///D:/JetBrains/workspace/h2/jdk/target/classes/static/android.png
        ///D:/JetBrains/workspace/h2/jdk/target/classes/com/zx/arch/resource/
        ///D:/JetBrains/workspace/h2/jdk/target/classes/

        // Paths.get(ClassTransformerTest.class.getResource("/").toURI())
    }

    public static void main(String[] args) {
        getImage();
        //����������ʹ��class������Դ,path������ĸ������� "/"
    }
}
