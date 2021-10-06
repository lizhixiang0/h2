package com.zx.arch.concurrency.connectionPool;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.util.concurrent.TimeUnit;

/**
 * 代理模式模拟 数据库连接
 * @author admin
 */
public class ConnectionDriver {

    private static String COMMIT_METHOD = "commit";

    static class ConnectionHandler implements InvocationHandler {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            // 调用commit方法后休眠0.1s
            if (method.getName().equals(COMMIT_METHOD)) {
                TimeUnit.MILLISECONDS.sleep(10);
            }
            return null;
        }
    }

    public static final Connection createConnection() {
        return (Connection) Proxy.newProxyInstance(ConnectionDriver.class.getClassLoader(), new Class<?>[] { Connection.class }, new ConnectionHandler());
    }
}
