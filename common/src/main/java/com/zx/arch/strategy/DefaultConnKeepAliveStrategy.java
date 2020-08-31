package com.zx.arch.strategy;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import org.apache.http.HttpResponse;
import org.apache.http.conn.ConnectionKeepAliveStrategy;
import org.apache.http.impl.client.DefaultConnectionKeepAliveStrategy;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author admin
 */
public class DefaultConnKeepAliveStrategy implements ConnectionKeepAliveStrategy {
    private static final Logger logger = LoggerFactory.getLogger(DefaultConnKeepAliveStrategy.class);
    private long maxIdleTime;

    public DefaultConnKeepAliveStrategy(long maxIdleTime) {
        if (maxIdleTime < 0L) {
            throw new IllegalArgumentException("maxIdleTime cannot be negative");
        } else {
            this.maxIdleTime = maxIdleTime;
        }
    }

    @Override
    public long getKeepAliveDuration(HttpResponse httpResponse, HttpContext httpContext) {
        long duration = DefaultConnectionKeepAliveStrategy.INSTANCE.getKeepAliveDuration(httpResponse, httpContext);
        return 0L < duration && duration < this.maxIdleTime ? duration : this.maxIdleTime;
    }
}
