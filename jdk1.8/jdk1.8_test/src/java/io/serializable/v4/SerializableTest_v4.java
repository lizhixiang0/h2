package io.serializable.v4;

import io.serializable.SerializableUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.*;

/**
 * @author lizx
 * @since 1.0.0
 * @description 强制自定义序列化
 * @blog "https://www.jianshu.com/p/352fa61e0512
 **/
public class SerializableTest_v4  {

    /**
     * 测试点1、实现Externalizable,强制自定义序列化,相比于Serializable更高效
     * 注意: 当读取对象时，会调用被序列化类的无参构造器去创建一个新的对象，然后再将被保存对象的字段的值分别填充到新对象中
     *       所以必须得有无参构造器！
     * https://www.tuicool.com/articles/2Q3M73
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        Girl girl  = new Girl("女","涂涂","18");

        SerializableUtils.serialize(girl,SerializableUtils.PATH);
        Object deserialize = SerializableUtils.deserialize(SerializableUtils.PATH);

        System.out.println(deserialize.toString());
    }


}

@Getter
@Setter
@ToString()
class Girl implements Externalizable {

    private static final long serialVersionUID = 1L;

    private String sex;
    private String name;
    private String age;

    public Girl() {
    }

    public Girl(String sex, String name, String age) {
        this.sex = sex;
        this.name = name;
        this.age = age;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeUTF(sex);
        out.writeUTF(name);
        out.writeUTF(age);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        this.sex = in.readUTF();
        this.name = in.readUTF();
        this.age = in.readUTF();
    }
}





