package com.zx.arch.auth.exception;


/**
 * @author admin
 */
public class ThirdpartyAuthenticationException extends VasAuthenticationException {
    public ThirdpartyAuthenticationException(int errorCode) {
        super(errorCode);
    }

    public ThirdpartyAuthenticationException(int errorCode, String message) {
        super(errorCode, message);
    }

    public ThirdpartyAuthenticationException(int errorCode, String message, Throwable ex) {
        super(errorCode, message, ex);
    }
}
