package com.wangwenjun.concurrent.chapter11;
/**
 * JDBC驱动如何加载？
 * @author admin
 *
 * 我们在com.wangwenjun.concurrent.chapter11包下创建了一个Animal接口,通常来讲,我们是直接将实现类和接口写在一起,但是如果我们想让第三方去实现这个接口，那需要解决什么问题？
 * 最主要的问题就是，我们如何将实现类加载进来！这里肯定是要使用到类加载器,但是以那种形式呢？
 * 一般来讲,我们直接使用即可,系统类加载器会直接从classpath找到第三方的jar包,然后加载实现类！
 * 但是针对一些启动类加载的接口则不行，这些接口在调用实现类方法时，根据classLoader的传播机制,他们会使用Bootstrap加载器去加载类,那肯定是加载不了的。
 * 所以,JDBC是如何解决这个问题的？？
 *
 */
public class JDBC {
    public static void main(String[] args) throws ClassNotFoundException {
        // Class.forName(String name)也遵循类的传递性,默认会使用调用类的类加载器来进行类加载，可以设置类加载器
        // 另外，上一章我们说过，使用反射方法会引发类的初始化，所以这里Class.for()会导致Driver的出初始化,并且运行期静态块,看com.mysql.jdbc.Driver的源码
        // 会执行 java.sql.DriverManager.registerDriver(new Driver()); ，这里使用到new关键字,所以会加载Driver类
        Class<?> aClass = Class.forName("com.mysql.jdbc.Driver");
        System.out.println(aClass.getClassLoader());   // sun.misc.Launcher$AppClassLoader

        // 5.1.5及之后的版本无需手动调用 Class.forName 方法来加载驱动,而是JDK使用SPI模式直接加载到驱动类
        // https://blog.csdn.net/qq_41894099/article/details/104558522
        // https://www.jianshu.com/p/f6653220a3e7


    }
}
