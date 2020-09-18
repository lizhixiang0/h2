package com.zx.arch.guava.BasicUtilities;

import static com.google.common.base.Preconditions.*;

/**
 * @author lizx
 * @description ���������һ����Ŀ�б���Ҫ���ǵ��ġ��������ǰ��Ҫ������˸�Ҫ�����������һ����Ŀ�Ľ�׳�ԺͰ�ȫ�ԡ�
 *              guava��Preconditions����Լ򵥣����ŵİ�������ʵ�ֲ�����顣
 * @since 1.0.0
 **/
public class PreconditionsTest {

    /**
     * �Լ���д������в����ж�
     */
    private static void a(int a, int b) {
        // Exception in thread "main" java.lang.IllegalArgumentException: Expected a > b, but 2 > 1
        checkArgument(a > b, "Expected a > b, but %s > %s", b, a);
    }

    /**
     * �жϲ����Ƿ�Ϊnull
     */
    private static void b(String a){
        // ���value�Ƿ�Ϊnull���÷���ֱ�ӷ���value ! ���a��null ��ֱ�ӱ�NPE
        a = checkNotNull(a);
    }

    /**
     * �ж϶���״̬
     */
    private static void c(boolean a){
        // ��true��IllegalStateException
        checkState(a);
    }

    /**
     * ���index��Ϊ����ֵ��ĳ���б��ַ����������Ƿ���Ч��index>=0 && index<size  ��������Χ��IndexOutOfBoundsException
     * @param index  ��Ҫ�õ�������
     * @param size   �����б��ַ���������Ĵ�С
     */
    private static void d(int index, int size){
        index = checkElementIndex(index,size);

        // ���index��Ϊλ��ֵ��ĳ���б��ַ����������Ƿ���Ч��index>=0 && index<=size *
        // ע���������Ե�ַ ֧��index = size
        // ����ֵ�����������б��ַ����������е�Ԫ�� ,λ��ֵ��λ�÷�Χ��������ȡ�б��ַ���������
        index = checkPositionIndex(index, size);
    }

    /**
     * ���[start, end]��ʾ��λ�÷�Χ��ĳ���б��ַ����������Ƿ���Ч*
     * @param start
     * @param end
     * @param size  �б��ַ���������Ĵ�С
     */
    private static void e(int start, int end, int size){
        checkPositionIndexes(start,end,size);
    }

    public static void main(String[] args) {
        // ʵս https://blog.csdn.net/qfycc92/article/details/44700869
        // ע����Щ���з���ֵ����Щ�����޷�������
    }
}
