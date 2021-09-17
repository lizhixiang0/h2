package lang.annotation;

import lombok.Data;

/**
 * @author lizx
 * @date 2021/9/16
 * @since FunctionalInterfaceע���˽�
 **/
@Data
public class FunctionalInterfaceTest {

        /*
            1����ע��ֻ�ܱ����"���ҽ���һ�����󷽷�"�Ľӿ��ϡ�

            2��JDK8�ӿ��еľ�̬������Ĭ�Ϸ������������ǳ��󷽷���

            3���ӿ�Ĭ�ϼ̳�java.lang.Object����������ӿ���ʾ����������Object�з�������ôҲ������󷽷���

            4����ע�ⲻ�Ǳ���ģ����һ���ӿڷ���"����ʽ�ӿ�"���壬��ô�Ӳ��Ӹ�ע�ⶼû��Ӱ�졣���ϸ�ע���ܹ����õ��ñ��������м�顣�����д�Ĳ��Ǻ���ʽ�ӿڣ����Ǽ�����@FunctionInterface����ô�������ᱨ��

            5�������ӿڵ�ʵ��������lambda���ʽ���������û��캯�����ô�����
        */

        public  String name = "FunctionalInterfaceTest";

        public void test1(){
            TestInterface<FunctionalInterfaceTest> testTestInterface = test -> {test.setName(test.name.substring(1)); };
            testTestInterface.sub(new FunctionalInterfaceTest());
        }

    public static void main(String[] args) {
        new FunctionalInterfaceTest().test1();
    }
}


/**
 * ��ȷ�ĺ���ʽ�ӿ�
 */
@FunctionalInterface
interface TestInterface<T> {


    /**
     * ���󷽷�
     */
    void sub(T t);

    /**
     * Object�еķ������ǳ��󷽷�
     * @param var1
     * @return
     */
    @Override
    boolean equals(Object var1);

    /**
     * default����
     */
    default void defaultMethod() {}

    /**
     * static����
     */
    static void staticMethod() {}
}