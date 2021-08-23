package io.serializable.v2;

import io.serializable.SerializableUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class SerializableTest_v2 implements Serializable {

    /**
     * 测试点1、父类非序列化，其子类进行序列化时,子类需要访问父类的无参构造,此时就算子类继承了父类的属性,也无法序列化父类的属性
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        Girl girl = new Girl("涂涂","18","女",new Boy("小象","18","男"));


        SerializableUtils.serialize(girl,SerializableUtils.PATH);
        Object deserialize = SerializableUtils.deserialize(SerializableUtils.PATH);

        System.out.println(deserialize.toString());
    }


}

@Getter
@Setter
@ToString
class Person{

    private static final long serialVersionUID = 1L;
    /**
     * 1、static修饰的属性是属于类,而非对象,所以无法被序列化
     * 2、如果不希望哪个属性被序列化,则用transient关键字修饰
     */
    private String name;
    private String age;

    public Person(String name, String age) {
        this.name = name;
        this.age = age;
    }

    public Person(){}
}

@Getter
@Setter
@ToString(callSuper=true)
class Girl extends Person implements Serializable{
    private String sex;
    private Boy boy;

    public Girl(String name, String age, String sex, Boy boy) {
        super(name, age);
        this.sex = sex;
        this.boy = boy;
    }

}


@Getter
@Setter
@ToString(callSuper=true)
class Boy extends Person implements Serializable{
    private String sex;

    public Boy(String name, String age, String sex) {
        super(name, age);
        this.sex = sex;
    }
}





