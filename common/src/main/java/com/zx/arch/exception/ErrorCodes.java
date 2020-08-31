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
            this.put(1, "Http Client Error");
            this.put(2, "Server side error");
            this.put(3, "Rest client error");
            this.put(4, "Keystore or trust store parameter error");
            this.put(5, "Http client init error");
            this.put(6, "RestTemplate init error");
        }
    };
}
