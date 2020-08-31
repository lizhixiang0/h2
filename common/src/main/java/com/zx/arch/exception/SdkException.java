package com.zx.arch.exception;

import com.zx.arch.exception.ErrorCodes;
import org.apache.commons.lang3.StringUtils;

public class SdkException extends Exception {
    private static final long serialVersionUID = 4285068898693711948L;
    private final int errorCode;
    private final String message;

    public SdkException(Throwable ex) {
        this(-1, "Unknow SDK Error", ex);
    }

    public SdkException(int errorCode) {
        this(errorCode, (String)null);
    }

    public SdkException(int errorCode, String message) {
        this(errorCode, message, (Throwable)null);
    }

    public SdkException(int errorCode, String message, Throwable ex) {
        super(ex);
        if (StringUtils.isEmpty(message)) {
            message = (String) ErrorCodes.CODE_MSG_MAPPING.get(errorCode);
            if (StringUtils.isEmpty(message)) {
                if (ex != null) {
                    message = ex.getMessage();
                } else {
                    message = "Unknow SDK Error";
                }
            }
        }

        this.message = message;
        this.errorCode = errorCode;
    }

    public String toString() {
        return "SdkException{errorCode=" + this.errorCode + ", message='" + this.message + '\'' + '}';
    }

    public int getErrorCode() {
        return this.errorCode;
    }
}
