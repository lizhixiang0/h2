package util.list;


import java.util.ArrayList;
import java.util.Iterator;

/**
 * @author lizx
 * @date 2021/8/19
 * @since
 **/
public class ArrayListTest {

    /**
     * 测试内部类Itr
     */
    public void testIter(){
        // 匿名内部类创建对象,意思是创建了一个ArrayList的子类,然后用这个子类创建对象,查看字节码可以发现额外产生了一个class文件,那个文件就是匿名类
        ArrayList array = new ArrayList<String>(){

            // 可以定义属性或方法
            private String name  = "Objects created by anonymous inner classes";

            public String getName(){return name;}

            // 构造代码块,会自动合并到构造函数里
            {
                add("aaa");
                add("bbb");
                add("ccc");
                add("ddd");
            }
        };

        // 好了,下面测试

        Iterator iterator = array.iterator();


    }

    public static void main(String[] args) {
        new ArrayListTest().testIter();
    }
}
