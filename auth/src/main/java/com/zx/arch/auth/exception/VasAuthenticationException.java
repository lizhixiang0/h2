package com.zx.arch.auth.exception;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import com.zx.arch.exception.GenericVasException;

public class VasAuthenticationException extends GenericVasException {
    public VasAuthenticationException(int errorCode) {
        super(errorCode);
    }

    public VasAuthenticationException(int errorCode, String message) {
        super(errorCode, message);
    }

    public VasAuthenticationException(int errorCode, String message, Throwable ex) {
        super(errorCode, message, ex);
    }
}
