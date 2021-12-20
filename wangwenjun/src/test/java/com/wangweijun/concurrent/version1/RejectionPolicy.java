package com.wangweijun.concurrent.version1;

/**
 * @author lizx
 * @date 2021/12/10
 * @since
 * @description ��������Ų��£���ԓ�оܽ^����
 **/
public interface RejectionPolicy {
    void handle();

    /**
     * ֱ���׳�����
     */
    public class ThrowExceptionPolicy implements RejectionPolicy {

        @Override
        public void handle() {
            throw new RuntimeException();
        }
    }
}
