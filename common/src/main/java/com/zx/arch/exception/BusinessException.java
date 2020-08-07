package com.zx.arch.exception;

import lombok.Data;


/**
 * @author Lenovo
 */
@Data
public class BusinessException extends RuntimeException {
    private static final long serialVersionUID = -1L;
    private int businessCode;
    private String message;


    public BusinessException(int businessCode) {
        super(String.valueOf(businessCode));
        this.businessCode = businessCode;
    }

    public BusinessException(int businessCode, String message) {
        this.businessCode = businessCode;
        this.message = message;
    }

    @Override
    public String toString() {
        return String.format("businessCode=%d, message=%s, this.businessCode, this.message");
    }
}

