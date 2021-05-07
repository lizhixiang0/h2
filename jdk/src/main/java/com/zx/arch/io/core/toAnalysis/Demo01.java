package com.zx.arch.io.core.toAnalysis;

import lombok.Data;

import java.io.*;

/**
 * @author lizx
 * @since 1.0.0
 * @descripiton 序列化和反序列化
 * @link "https://cxyroad.blog.csdn.net/article/details/108988916
 **/
public class Demo01 {

    @Data
    public static class FlyPig implements Serializable{
        // 本来这个是根据类属性和方法计算出来的值,所以如果序列化之后增加一个属性，此时反序列化会报错（我们要避免这种情况）
        private static final long serialVersionUID = 1L;
        // 静态属性不参与序列化
        private static String AGE = "269";
        private String name;
        private String color;
        // 透明属性也不参与序列化,IO里面有个Externalizable接口也可以控制某些属性不参与序列化
        // https://www.cnblogs.com/chenfei0801/archive/2013/04/06/3002146.html
        transient private String car;

        //private String addTip;

        @Override
        public String toString() {
            return "FlyPig{" +
                    "name='" + name + '\'' +
                    ", color='" + color + '\'' +
                    ", car='" + car + '\'' +
                    ", AGE='" + AGE + '\'' +
                    '}';
        }
    }

    /**
     * 1、序列化
     */
    private static void serializeFlyPig() throws IOException {
        FlyPig flyPig = new FlyPig();
        flyPig.setColor("black");
        flyPig.setName("naruto");
        flyPig.setCar("0000");
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\resources\\static\\IOTest\\flyPig.txt")));
        oos.writeObject(flyPig);
        System.out.println("FlyPig 对象序列化成功！");
        oos.close();
    }

    /**
     * 2、反序列化
     */
    private static FlyPig deserializeFlyPig() throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\resources\\static\\IOTest\\flyPig.txt")));
        FlyPig person = (FlyPig) ois.readObject();
        System.out.println("FlyPig 对象反序列化成功！");
        return person;
    }

    public static void main(String[] args) throws Exception {
        serializeFlyPig();
        FlyPig flyPig = deserializeFlyPig();
        System.out.println(flyPig.toString());

        System.out.println( Integer.class.isPrimitive());
        System.out.println(String.class instanceof Serializable);

    }

}
