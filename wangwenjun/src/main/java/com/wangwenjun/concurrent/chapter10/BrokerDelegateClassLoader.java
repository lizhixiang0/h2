package com.wangwenjun.concurrent.chapter10;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 除了绕过系统类加载器,我们也可以通过实现loadClass来破坏掉双亲加载机制！
 *
 * 其实之所以遵守双亲加载机制就是通过loadClass来实现的，子类加载器会调用父类的类加载器来加载！那么如果重写了loadClass，使其不去调用父类的类加载器，自然就不需要遵守双亲加载机智了
 * @author admin
 */
public class BrokerDelegateClassLoader extends ClassLoader {

    private final static Path DEFAULT_CLASS_DIR = Paths.get("D:\\JetBrains\\workspace\\h2\\wangwenjun\\target\\classes");

    private final Path classDir;

    public BrokerDelegateClassLoader() {
        super();
        this.classDir = DEFAULT_CLASS_DIR;
    }

    public BrokerDelegateClassLoader(String classDir) {
        super();
        this.classDir = Paths.get(classDir);
    }

    public BrokerDelegateClassLoader(String classDir, ClassLoader parent) {
        super(parent);
        this.classDir = Paths.get(classDir);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] classBytes = this.readClassBytes(name);
        if (null == classBytes || classBytes.length == 0) {
            throw new ClassNotFoundException("Can not load the class " + name);
        }
        return this.defineClass(name, classBytes, 0, classBytes.length);
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        // 根据类的全路径名进行加锁，保证多线程下只被加载一次
        synchronized (getClassLoadingLock(name)) {
            // 到已加载类的缓存中查看该类是否被加载,类加载器在成功加载某个类之后，会把得到的类的实例缓存起来。下次再请求加载该类的时候，类加载器会直接使用缓存的类的实例，而不会尝试再次加载。也就是说，对于一个类加载器实例来说，相同全名的类只加载一次，即 loadClass方法不会被重复调用。
            Class<?> klass = findLoadedClass(name);
            if (klass == null) {
                // 如果没加载则进行加载，如果是以java或者javax开头，则委托系统类加载器进行加载，如果不是则使用自定义加载器加载
                if (name.startsWith("java.") || name.startsWith("javax")) {
                    try {
                        klass = getSystemClassLoader().loadClass(name);
                    } catch (Exception e) {
                        //ignore
                    }
                } else {
                    try {
                        klass = this.findClass(name);
                    } catch (ClassNotFoundException e) {
                        //ignore
                    }
                    // 如果自定义类加载器加载失败，则委托父类加载器进行加载或者还是让系统类进行加载
                    if (klass == null) {
                        if (getParent() != null) {
                            klass = getParent().loadClass(name);
                        } else {
                            klass = getSystemClassLoader().loadClass(name);
                        }
                    }
                }
            }
            if (klass == null) {
                throw new ClassNotFoundException("The class " + name + " not found.");
            }
            if (resolve) {
                resolveClass(klass);
            }
            return klass;
        }
    }

    private byte[] readClassBytes(String name) throws ClassNotFoundException {
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
        return "Broker Delegate ClassLoader";
    }
}