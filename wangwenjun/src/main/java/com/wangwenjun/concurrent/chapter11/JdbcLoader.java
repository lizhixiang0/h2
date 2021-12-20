package com.wangwenjun.concurrent.chapter11;

import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * 通过Class.forName和通过SPI加载JDBC驱动有什么区别？
 *  https://blog.csdn.net/qq_41894099/article/details/104558522
 *
 * @author admin
 */
public class JdbcLoader {
    public static void main(String[] args) throws ClassNotFoundException, SQLException {
        // Class.forName(String name)也遵循类的传递性,默认会使用调用类的类加载器来进行类加载，可以设置类加载器
        // 另外，上一章我们说过，使用反射方法会引发类的初始化，看源码,这里Class.forName()会调用forName0并且传递类加载器,这是个本地方法。（这个本地方法估计就是去进行类的加载了）
        // 然后类初始化会运行期静态块,我们看com.mysql.jdbc.Driver的源码 ，静态代码块中会调用 java.sql.DriverManager.registerDriver(new Driver()) 从而完成Driver注册
        Class<?> aClass = Class.forName("com.mysql.jdbc.Driver");
        System.out.println(aClass.getClassLoader());   // sun.misc.Launcher$AppClassLoader

        // JDBC 5.1.5及之后的版本无需手动调用 Class.forName 方法来加载驱动,而是JDK使用SPI模式直接加载到驱动类
        // 在使用DriverManager.getConnection()获取连接时会触发DriverManager类的加载,
        // 我们可以看到DriverManager类中的静态代码块，会执行loadInitialDrivers();
        //  这个方法使用了ServiceLoader.load(Driver.class); (这里使用到了SPI)
        DriverManager.getConnection("");

    }
}
