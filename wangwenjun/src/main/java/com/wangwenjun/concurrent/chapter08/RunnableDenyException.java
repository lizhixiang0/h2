package com.wangwenjun.concurrent.chapter08;

/**
 * @author admin
 */
public class RunnableDenyException extends RuntimeException {

    public RunnableDenyException(String message)
    {
        super(message);
    }
}