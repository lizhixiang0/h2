package com.zx.arch.socket;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

/**
 * @author lizx
 * @since 1.0.0
 * @description 模拟客户端
 **/
public class Client {
    public static void main(String[] args) throws IOException {
        long timeMillis = System.currentTimeMillis();
        Socket socket=new Socket();
        // 1秒钟连不上就报错
        socket.connect(new InetSocketAddress("127.0.0.1",8888),1000);
        // 5秒钟内收不到任何信息就报错
        socket.setSoTimeout(4000);

        OutputStream os=socket.getOutputStream();
        os.write("服务端你好".getBytes());
        InputStream is=socket.getInputStream();
        byte[] bytes=new byte[1024];
        is.read(bytes);
        System.out.println(new String(bytes));
        socket.close();
        System.out.println(System.currentTimeMillis()-timeMillis);
    }
}
