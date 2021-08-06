package io.serializable;

import java.io.*;

/**
 * @author lizx
 * @since 1.0.0
 * @description  序列化问题,"https://freeman.blog.csdn.net/article/details/99304762
 **/
public class SerializableUtils {

    public final static String PATH = "D:\\JetBrains\\workspace\\h2\\jdk1.8\\jdk1.8_test\\src\\java\\io\\serializable\\girl.txt";

    public static void serialize(Object object,String pathname) throws Exception {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File(pathname)));
        oos.writeObject(object);
        oos.close();
    }
    /**
     * @author xzf
     * @description 反序列化
     * @date 2020/2/22 19:34
     */
    public static Object deserialize(String pathname) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File(pathname)));
        return ois.readObject();
    }

}
