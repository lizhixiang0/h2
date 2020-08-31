package com.zx.arch.response;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

import java.io.Serializable;

/**
 * @author admin
 */
public class ErrorResponse implements Serializable {
    private static final long serialVersionUID = -5928734041858787180L;
    private int errorCode;
    private String message;

    public int getErrorCode() {
        return this.errorCode;
    }

    public String getMessage() {
        return this.message;
    }

    public void setErrorCode(final int errorCode) {
        this.errorCode = errorCode;
    }

    public void setMessage(final String message) {
        this.message = message;
    }

    public ErrorResponse() {
    }

    public ErrorResponse(final int errorCode, final String message) {
        this.errorCode = errorCode;
        this.message = message;
    }
}
