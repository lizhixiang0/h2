package com.wangwenjun.concurrent.chapter09;

/**
 * 测试,请说出test1和test2 的打印结果和理由！

 *
 * @author admin
 */
public class Singleton
{
    /**
     * 在对这个属性进行new Singleton() 赋值时，类的记载已经进行了！也就说说，这里调用只会调用一下构造方法，不会再有其他动作
     *
     * 在生成的clinit方法里,instance和其他变量，例如 x、y没什么区别，都是按class中顺序进行赋值的
     */
    private static Singleton instance = new Singleton();

    private static int x = 0;

    private static int y;



    public Singleton() {
        x++;
        y++;
    }

    public static Singleton getInstance()
    {
        return instance;
    }

    /**
     *
     *  首先调用getInstance,这是个静态方法,会触发类的加载和初始化，然后进入类的加载阶段，经过加载阶段和连接阶段 （此时instance = null ；x = 0 ; y = 0），最后进入初始化阶段
     *  调用clinit方法,其中会对三个变量进行赋值,首先是调用Singleton构造方法生成Singleton对象赋值给instance变量，此时构造方法会执行
     *  x++ 、y++ ,然后继续进行x = 0赋值, y则不做任何操作！ clinit方法执行完毕！
     *  最终结果: x = 0 ; y = 1
     *
     *  由这题我们看到，构造方法不一定是在clinit初始化方法后面执行！
     */
    public static void test1(){
        Singleton singleton = Singleton.getInstance();
        System.out.println(x);  // 0
        System.out.println(y);  // 1
    }

    /**
     * 首先使用new创建Singleton对象，会触发类的初始化，然后进入类的加载阶段，经过加载阶段和连接阶段 （此时instance = null ；x = 0 ; y = 0）,最后进入初始化阶段
     * 调用clinit方法,其中会对三个变量进行赋值,首先是调用Singleton构造方法生成Singleton对象赋值给instance变量，此时构造方法会执行
     * x++ 、y++ ,然后继续进行x = 0赋值, y则不做任何操作！ clinit方法执行完毕！ （此时instance = xx ；x = 0 ; y = 1）
     * 然后继续执行构造方法,执行 x++ ；y++
     * 最终结果: x = 1; y = 2
     */
    public static void test2(){
        Singleton singleton = new Singleton();
        System.out.println(x);  // 1
        System.out.println(y);  // 2
    }

    public static void main(String[] args){
        test2();
    }

}
