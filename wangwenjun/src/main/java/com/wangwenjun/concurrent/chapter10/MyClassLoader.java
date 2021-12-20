package com.wangwenjun.concurrent.chapter10;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 自定义加载器通过继承ClassLoader并实现findClass来实现 ！findClass是loadClass方法里面调用的,会遵守双亲加载，如果想把双亲加载破坏掉，那就直接改写loadClass方法
 * @author admin
 * @自定义类加载器实例: “https://www.cnblogs.com/panxuejun/p/5885094.html
 */
public class MyClassLoader extends ClassLoader {
    // 定义默认的class存放路径
    private final static Path DEFAULT_CLASS_DIR = Paths.get("D:\\JetBrains\\workspace\\h2\\wangwenjun\\target\\classes");

    private final Path classDir;

    public MyClassLoader() {
        super();
        this.classDir = DEFAULT_CLASS_DIR;
    }

    public MyClassLoader(String classDir) {
        super();
        this.classDir = Paths.get(classDir);
    }

    /**
     * 可以指定类路径和父类加载器
     * @param classDir
     * @param parent
     */
    public MyClassLoader(String classDir, ClassLoader parent) {
        super(parent);
        this.classDir = Paths.get(classDir);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        // 读取class的二进制流
        byte[] classBytes = this.readClassBytes(name);
        if (null == classBytes || classBytes.length == 0)
        {
            throw new ClassNotFoundException("Can not load the class " + name);
        }
        // 调用defineClass定义class，可以看看defineClass的源码就知道为什么不能自定义java.lang.String
        return this.defineClass(name, classBytes, 0, classBytes.length);
    }

    private byte[] readClassBytes(String name) throws ClassNotFoundException {
        // 将包名分隔符转换为文件路径分隔符
        String classPath = name.replace(".", "/");
        Path classFullPath = classDir.resolve(Paths.get(classPath + ".class"));
        if (!classFullPath.toFile().exists()) {
            throw new ClassNotFoundException("The class " + name + " not found.");
        }
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Files.copy(classFullPath, baos);
            return baos.toByteArray();
        } catch (IOException e) {
            throw new ClassNotFoundException("load the class " + name + " occur error.", e);
        }
    }

    @Override
    public String toString()
    {
        return "My ClassLoader";
    }
}