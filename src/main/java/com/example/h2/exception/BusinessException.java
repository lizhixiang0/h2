package com.example.h2.exception;

import java.util.Arrays;

public class BusinessException extends RuntimeException {
    private static final long serialVersionUID = -1L;
    private int businessCode;
    private String message;
    private String[] args;

    public BusinessException(int businessCode) {
        super(String.valueOf(businessCode));
        this.businessCode = businessCode;
    }

    public BusinessException(int businessCode, String message) {
        this.businessCode = businessCode;
        this.message = message;
    }

    public BusinessException(int businessCode, String message, String... args) {
        this.businessCode = businessCode;
        this.message = message;
        this.args = args;
    }

    public int getBusinessCode() {
        return this.businessCode;
    }

    public void setBusinessCode(int businessCode) {
        this.businessCode = businessCode;
    }

    @Override
    public String getMessage() {
        return this.message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String[] getArgs() {
        return this.args;
    }

    public Object[] getArgObjects() {
        if (this.args == null) {
            return null;
        } else {
            Object[] objArgs = new Object[this.args.length];
            int i = 0;
            String[] var3 = this.args;
            int var4 = var3.length;

            for(int var5 = 0; var5 < var4; ++var5) {
                String arg = var3[var5];
                objArgs[i++] = arg;
            }

            return objArgs;
        }
    }

    public void setArgs(String[] args) {
        this.args = args;
    }

    @Override
    public String toString() {
        return String.format("businessCode=%d, message=%s, args=%s", this.businessCode, this.message, Arrays.toString(this.args));
    }
}

