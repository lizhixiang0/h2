package com.wangweijun.concurrent.version1;

/**
 * @author lizx
 * @date 2021/12/10
 * @since
 * @description 如果容器放不下，應該有拒絕策略
 **/
public interface RejectionPolicy {
    void handle();

    /**
     * 直接抛出異常
     */
    public class ThrowExceptionPolicy implements RejectionPolicy {

        @Override
        public void handle() {
            throw new RuntimeException();
        }
    }
}
