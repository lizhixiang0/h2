package com.zx.arch.handler;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

import java.io.IOException;
import java.net.UnknownHostException;
import javax.net.ssl.SSLException;
import org.apache.http.HttpRequest;
import org.apache.http.NoHttpResponseException;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.Args;

/**
 * @author admin
 */
public class PaxDefaultRetryHandler extends DefaultHttpRequestRetryHandler {
    public PaxDefaultRetryHandler(final int retryCount, final boolean requestSentRetryEnabled) {
        super(retryCount, requestSentRetryEnabled);
    }

    @Override
    public boolean retryRequest(final IOException exception, final int executionCount, final HttpContext context) {
        Args.notNull(exception, "Exception parameter");
        Args.notNull(context, "HTTP context");
        if (executionCount > this.getRetryCount()) {
            return false;
        } else if (exception instanceof UnknownHostException) {
            return false;
        } else if (exception instanceof SSLException) {
            return false;
        } else if (exception instanceof NoHttpResponseException) {
            return true;
        } else {
            HttpClientContext clientContext = HttpClientContext.adapt(context);
            HttpRequest request = clientContext.getRequest();
            if (this.handleAsIdempotent(request)) {
                return true;
            } else {
                return !clientContext.isRequestSent() || this.isRequestSentRetryEnabled() && exception instanceof ConnectTimeoutException;
            }
        }
    }
}
