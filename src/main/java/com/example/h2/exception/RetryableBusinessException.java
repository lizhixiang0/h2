package com.example.h2.exception;

/**
 * @author lizx
 * @date 2020/07/20
 **/
public class RetryableBusinessException extends BusinessException {
    private static final long serialVersionUID = 6990145249937373188L;

    public RetryableBusinessException(int businessCode) {
        super(businessCode);
    }

    public RetryableBusinessException(int businessCode, String message) {
        super(businessCode, message);
    }

    public RetryableBusinessException(int businessCode, String message, String... args) {
        super(businessCode, message, args);
    }
}
