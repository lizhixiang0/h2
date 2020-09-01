package com.zx.arch.exception;

import lombok.Data;
import lombok.Getter;

/**
 * @author  lizx
 * @since   1.0.0
 * @date    2020/06/09
 **/
@Data
public class AuthFailureException extends RuntimeException {
    private static final long serialVersionUID = -8468240335395380182L;
    @Getter
    private final int errorCode;

    public AuthFailureException(int bizCode) {
        this.errorCode = bizCode;
    }

}
