package com.example.h2.exception;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//



public class ServiceException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private int businessCode;
    private String message;
    private String[] args;

    public ServiceException() {
    }

    public ServiceException(int businessCode) {
        this.setBusinessCode(businessCode);
    }

    public ServiceException(String message) {
        this.setBusinessCode(999);
        this.setMessage(message);
    }

    public ServiceException(int businessCode, String message) {
        this.setMessage(message);
        this.setBusinessCode(businessCode);
    }

    public ServiceException(int businessCode, String message, String... args) {
        this.setMessage(message);
        this.setBusinessCode(businessCode);
        this.setArgs(args);
    }

    public ServiceException(Throwable cause) {
        super(cause);
        this.setBusinessCode(999);
    }

    public ServiceException(String message, Throwable cause) {
        this(cause);
        this.setMessage(message);
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
        return this.getClass().getName() + " [businessCode=" + this.businessCode + ", message=" + this.message + "]";
    }
}
