package io.serializable;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.*;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class SerializableTest_v1 implements Serializable {

    /**
     * 测试点1、父类实现序列化,子类可以直接序列化
     * 测试点2、类中的引用变量需要实现序列化,不然在序列化时会抛出异常
     * 测试点3、static属性不可序列化、transient表示属性不需要序列化
     * 测试点4、serialVersionUID的作用理解
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        Girl girl = new Girl();
        girl.setSex("女");
        girl.setAge("18");
        girl.setName("涂涂");

        Boy boy = new Boy();
        boy.setSex("男");
        girl.setBoy(boy);

        SerializableUtils.serialize(girl,SerializableUtils.PATH);
        Object deserialize = SerializableUtils.deserialize(SerializableUtils.PATH);

        System.out.println(deserialize.toString());
    }


}

@Getter
@Setter
@ToString
class Person implements Serializable{

    /**
     *  在序列化存储/反序列化时,JVM会把传来的字节流中的serialVersionUID与本地相应实体类的serialVersionUID进行比较
     *  如果相同就认为是一致的，可以进行反序列化，否则就会出现序列化版本不一致的异常。
     *  如果不设置，jvm会根据类的内容自动生成 serialVersionUID,如果对类的源代码作了修改再重新编译,
     *  新生成的类文件的serialVersionUID值会发生变化。且类的serialVersionUID完全依赖于Java编译器的实现
     *  对于同一个类，用不同的Java编译器编译，也有可能会导致不同的serialVersionUID。
     *  所以,通常我们会设置为一个常量,且越容易比较越好
     *  这样就可以来实现来实现新旧实体类的兼容性,比如只追加了一个附加信息字段,接收方的类里即使没有也不影响反序列化
     */
    private static final long serialVersionUID = 1L;
    /**
     * 1、static修饰的属性是属于类,而非对象,所以无法被序列化
     * 2、如果不希望哪个属性被序列化,则用transient关键字修饰
     */
    private String name;
    private String age;

}

@Getter
@Setter
@ToString(callSuper=true)
class Girl extends Person {
    private String sex;
    /**
     * 引用属性也必须实现序列化,如果不实例化,在运行时将引发不可序列化异常NotSerializableException
     */
    private Boy boy;
}


@Getter
@Setter
@ToString
class Boy{
    private String sex;
}





