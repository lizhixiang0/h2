package com.zx.arch.exception;

import java.util.HashMap;
import java.util.Map;

/**
 * @author lizx
 * @date 2020/08/06
 **/
public interface ErrorCodes {
    /**
     * 未知错误,没有用business处理的就是未知错误
     */
    int UNKNOWN = 999;
    Map<String, String> CODE_MSG_MAPPING = new HashMap() {
        {
            this.put(11, "Invalid parameter");
            this.put(12, "Invalid parameter 'timestamp'");
            this.put(13, "Authentication failed");
            this.put(14, "Authentication failed");
            this.put(15, "Authentication failed");
            this.put(16, "Authentication failed");
            this.put(17, "Auth failed");
            this.put(18, "Auth failed");
            this.put(19, "Vas Common Configuration Error");
            this.put(99, "Unknow error");
        }
    };
}
