package com.example.h2.exception;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.validation.FieldError;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public final class ErrorResponse implements Serializable {

    private static final long serialVersionUID = 1L;

    @JsonProperty
    @Getter
    private final HttpStatus status;
    @JsonProperty
    @Getter
    private final String message;
    @JsonProperty
    @Getter
    private final int errorCode;
    @JsonProperty
    @Getter
    private final Date timestamp;

    @Getter
    private List<FieldError> errors;

    public ErrorResponse(final String message, final int errorCode, HttpStatus status) {
        this.message = message;
        this.errorCode = errorCode;
        this.status = status;
        this.timestamp = new Date();
    }

    public static ErrorResponse of(final String message, final int errorCode, HttpStatus status) {
        return new ErrorResponse(message, errorCode, status);
    }

    public ErrorResponse addFiledError(FieldError fe) {
        if(fe == null) {
            return this;
        }
        if(errors == null) {
            errors = new ArrayList<FieldError>();
        }
        errors.add(fe);
        return this;
    }
}
