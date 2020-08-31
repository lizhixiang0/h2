package com.zx.arch.auth.handler;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author admin
 */
public interface ResponseHandler {
    void handle(Throwable exception, HttpServletRequest request, HttpServletResponse response) throws IOException;
}
