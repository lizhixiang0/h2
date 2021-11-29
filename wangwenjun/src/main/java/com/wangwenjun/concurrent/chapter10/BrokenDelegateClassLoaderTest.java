package com.wangwenjun.concurrent.chapter10;

/***************************************
 * @author:Alex Wang
 * @Date:2017/11/21
 * QQ: 532500648
 * QQ群:463962286
 ***************************************/
public class BrokenDelegateClassLoaderTest
{
    public static void main(String[] args) throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        // 这里不需要特意设置父类加载器来绕过双亲机制了!
        BrokerDelegateClassLoader loader = new BrokerDelegateClassLoader();
        Class<?> aClass = loader.loadClass("com.wangwenjun.concurrent.chapter10.HelloWorld");
        Object helloWorld = aClass.newInstance();

    }
}
