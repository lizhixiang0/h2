package com.zx.arch.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;

/**
 * @author lizx
 * @date 2021/10/13
 * @since
 * @description Java内置的web应用服务器,'https://www.cnblogs.com/aspwebchh/p/8300945.html
 **/
public class HttpServerTest {
    public static void main(String[] arg) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8001), 0);
        // 设置线程池
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/test", new PingHandler());
        server.start();
    }

    static  class PingHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] data = "OK".getBytes(StandardCharsets.UTF_8.toString());
            exchange.sendResponseHeaders(200, data.length);//200, content-length
            OutputStream os = exchange.getResponseBody();
            os.write(data);
            os.close();
        }
    }
}
