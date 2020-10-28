package com.zx.arch.guava.BasicUtilities;

import com.google.common.base.Throwables;

import java.io.IOException;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 * @blog  "http://ifeve.com/google-guava-throwables/"
 * @note  ������� https://www.cnblogs.com/peida/p/Guava_Throwables.html
 **/
public class ThrowableTest {

    /**
     * Ϊʲô����Ҫ��ô�鷳��
     * ͨ������ֱ���׳��쳣���ɣ����������Ҫ���쳣����ش�������ͳ���쳣��
     * �Ǿ���Ҫ�õ��쳣��������������׳�ȥ��
     */
    public static void a(){
        throw new ArrayIndexOutOfBoundsException();
    }

    /**
     * ��֪��ʲô�쳣������NPP�쳣��ͳ�����ٴ��׳�
     * throwIfInstanceOf()
     * Throwable����Ϊָ�����쳣���׳�,ָ�������쳣���׳�,����������׳�  ������������ܼ컹�ǲ��ܼ죩
     */
    public static void b() throws IOException {
        try {
            throw new NullPointerException();
        } catch (Throwable t) {
            //�����׳�
            Throwables.throwIfInstanceOf(t,NullPointerException.class);
            Throwables.throwIfInstanceOf(t,IOException.class);
        }
    }

    /**
     * ��֪����ʲô�쳣,��������ܼ��쳣�����겻�׳���IO�쳣��������ǲ��ܼ��쳣��NPP�쳣���������׳�
     * throwIfUnchecked()
     * Throwable����ΪError��RuntimeException���׳� (���ܼ��쳣),NPP���������쳣�����Ի��׳�
     */
    public static void c(){
        try {
            throw new NullPointerException();
        } catch (Throwable t) {
            // todo
            // �����׳�
            Throwables.throwIfUnchecked(t);
        }
    }

    /**
     * ��֪����ʲô�쳣�����Ǵ�����ȫ���׳���
     * throwIfUnchecked()
     * Throwable����ΪError��RuntimeException���׳� () ,IO���ܼ��쳣�����Բ����׳�
     * ��ô,�ܼ��쳣�����ֱ��throw  ,Ҳ������RuntimeException��װ���׳�
     * Ϊ�˲�Ӱ����÷��ģ�����ʹ��RuntimeException��װ���׳�!
     */
    public static void d() {
        try {
            throw new IOException();
        } catch (Throwable t) {
            // todo
            //�����׳�
            Throwables.throwIfUnchecked(t);
            throw new RuntimeException(t);
        }
    }


    /**
     *  �о��쳣����������
     */
    public static void e(){
        try {
            throw new IOException();
        } catch (Throwable t) {
            String string = Throwables.getStackTraceAsString(t);
            Throwable throwable =  Throwables.getRootCause(t);
            List<Throwable> list = Throwables.getCausalChain(t);

            System.out.println(string);
            System.out.println(throwable.toString());
            System.out.println(list.get(0));
        }
    }

    public static void main(String[] args){
        // a();
        // b();
        // c();
        e();
    }
}
