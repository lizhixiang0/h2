package com.zx.arch.parameter;

/**
 * @author lizx
 * @since 1.0.0
 * @���Բ�������
 **/
public class Test {

    public static void testParameter(People people){
        people.setName("sss");
    }

    public static void main(String[] args) {
        People people = new People();
        testParameter(people);
        System.out.println(people.getName());
        //�ó�����: ���ݶ���ʱ�����ԶԶ�����в���!��Ϊ���ݵ��ǵ�ַ���Ե�ַ���в������ջ���ͬһ������
    }
}
