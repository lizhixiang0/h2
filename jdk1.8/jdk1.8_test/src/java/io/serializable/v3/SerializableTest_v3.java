package io.serializable.v3;

import io.serializable.SerializableUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.IOException;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.security.Permission;

/**
 * @author lizx
 * @since 1.0.0
 * @description  单例模式的类实现序列化接口,若使用默认的序列化策略，则在反序列化返回的对象不符合单利模式,如何解决？
 * @blog "https://www.jianshu.com/p/352fa61e0512
 **/
public class SerializableTest_v3 implements Serializable {

    /**
     * 测试点1、在序列话和反序列化过程中进行自定义操作,比如序列化时将女改成男！比如反序列化时将涂涂改成阿祥！
     * 测试点2、替换序列化的对象或替换反序列化生成的对象
     * 测试点3、序列化之后通过继承扩展属性后，反序列化填充父类属性值
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        Girl girl = Girl.getGirlInstance();
        girl.setSex("女");

        // SerializableUtils.serialize(girl,SerializableUtils.PATH);
        Girl deserialize = (Girl)SerializableUtils.deserialize(SerializableUtils.PATH);
        // 可以通过修改readResolve方法来保证单例
        assert girl == deserialize;

        System.out.println(deserialize);
    }


}

@Getter
@Setter
@ToString
class Person implements Serializable{

    public static final long serialVersionUID = 1L;
    /**
     * 1、static修饰的属性是属于类,而非对象,所以无法被序列化
     * 2、如果不希望哪个属性被序列化,则用transient关键字修饰
     */
    private String name;
    private String age;

    public Person(){}

    /**
     * 用来保证通过继承扩容后对老版本的兼容性
     * 比如类 Girl 被序列化到硬盘后,接着让Girl继承Person,为了保证用新的Girl成功反序列化硬盘里的数据且Person类的成员有默认值
     * 则可以在 Person 类中是实现readObjectNoData方法,定义Person类的成员默认值
     *
     */
    private void readObjectNoData() throws ObjectStreamException{
        this.name = "涂涂";
        this.age = "18";
    }
}

@Getter
@Setter
@ToString(callSuper=true)
class Girl  extends Person implements Serializable{
    /**
     * 子类自己要写一个serialVersionUID,继承父类的也没用
     */
    //private static final long serialVersionUID = 1L;

    private String sex;

    private static Girl girl = new Girl();

    private Girl(){}

    public static Girl getGirlInstance(){
        return girl;
    }

    /**
     * 自定义序列化,可用于加密密码
     *
     * 注意：read()的顺序要和write()的顺序一致。比如说序列化时写的顺序是name、age、sex反序列化时读的顺序也要是name、age、sex
     * @param out
     * @throws IOException
     */
//    private void writeObject(java.io.ObjectOutputStream out) throws IOException {
//        // out.defaultWriteObject();  将当前类的非静态和非瞬时字段写入此流 （默认序列化调用的这个）
//        out.writeObject(this.getName());
//        out.writeObject(this.getAge());
//        out.writeObject("男");
//    }

    /**
     * 自定义反序列化，可用于对数据进行约束！比如年龄不能小于0
     * @param in
     * @throws IOException
     * @throws ClassNotFoundException
     */
//    private void readObject(java.io.ObjectInputStream in) throws IOException,ClassNotFoundException {
//        // in.defaultReadObject();  从此流读取当前类的非静态和非瞬态字段 (默认反序列化调用这个)
//        in.readObject();// to skip first column
//        girl.setName("阿祥");
//        girl.setAge((String)in.readObject());
//        this.setSex((String)in.readObject());
//    }

    /**
     * 替换被序列化的对象,会先自动调用writeReplace()方法，用返回的这个对象，替换要序列化的那个对象，再进行序列化。就是说，实际序列化的是writeReplace()返回的这个对象，并不是原来的对象
     * @return
     */
//    private  Object  writeReplace(){
//        Girl girl = new Girl();
//        girl.setName("小猪");
//        girl.setSex("公");
//        girl.setAge("1000");
//        return girl;
//    }

    /**
     * 替换反序列化生成的对象 ,可用于保证单例
     * @return
     * @throws ObjectStreamException
     */
//    private Object readResolve() throws ObjectStreamException {
//        // 不管序列化的操作是什么，返回的都是本地的单例对象
//        return Girl.getGirlInstance();
//    }

















}





