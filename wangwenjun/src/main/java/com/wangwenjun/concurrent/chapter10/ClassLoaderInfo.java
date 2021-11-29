package com.wangwenjun.concurrent.chapter10;

/**
 * JVM中内置了三种类加载器,用来加载不同路径的类！这三种类加载器都遵守父委托机制（双亲加载机制）！
 *
 * 另外支持自定义类加载器！这个属于第四种吧！自定义加载器的父加载器是系统类加载器！
 *
 * @author admin
 */
public class ClassLoaderInfo
{
    /**
     * 根加载器，由c++实现
     */
    public static void bootStrap_classLoader(){
        // String的类加载器是根加载器，根加载器是c++编写的,所以获取不到相关引用 （侧面证明了String类是根加载器加载的）
        System.out.println("Bootstrap:" + String.class.getClassLoader());
        // 根加载器的加载路径可以通过sun.boot.class.path获取,可以通过设置-Xbootclasspath来设置根加载器的加载路径
        for(String s :System.getProperty("sun.boot.class.path").split(";")){
            System.out.println(s);
        }
    }

    /**
     * 扩展类加载器,由java实现,是java.lang.URLClassLoader的子类，完整类名是 sun.misc.Launcher$ExtClassLoader
     *
     * 可以将自己写的jar包放到扩展类路径中,这个加载器可以加载到！它的父加载器是根加载器
     */
    public static void ext_classLoader(){
        // 根加载器的加载路径可以通过sun.boot.class.path获取,可以通过设置-Xbootclasspath来设置根加载器的加载路径
        for(String s :System.getProperty("java.ext.dirs").split(";")){
            System.out.println(s);
        }
    }

    /**
     * 系统类加载器,负载加载classpath下的类库资源，比如我们在项目开发中引用的第三方jar包。完整类名是sun.misc.Launcher$AppClassLoader
     * 它的父加载器是扩展类加载器
     *
     * 系统里加载器的加载路径可以用-classpath 或者 -cp指定
     */
    public static void application_classLoader(){
        for(String s :System.getProperty("java.class.path").split(";")){
            System.out.println(s);
        }
        // 里面会包括：D:\JetBrains\workspace\h2\wangwenjun\target\classes,这应该是idea自动帮我们设置的类路径
        System.out.println(ClassLoaderInfo.class.getClassLoader());
    }

    public static void main(String[] args)
    {
        bootStrap_classLoader();
    }
}
