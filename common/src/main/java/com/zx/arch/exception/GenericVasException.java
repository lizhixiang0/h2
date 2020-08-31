package com.zx.arch.exception;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


/**
 * @author admin
 */
public class GenericVasException extends RuntimeException {
    private static final long serialVersionUID = 8859105159955024931L;
    private final int errorCode;
    private final String message;

    public GenericVasException(int errorCode) {
        this(errorCode, (String)null, (Throwable)null);
    }

    public GenericVasException(int errorCode, String message) {
        this(errorCode, message, (Throwable)null);
    }

    public GenericVasException(int errorCode, String message, Throwable ex) {
        super(ex);
        this.message = message;
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return this.errorCode;
    }

    @Override
    public String getMessage() {
        return this.message;
    }
}
