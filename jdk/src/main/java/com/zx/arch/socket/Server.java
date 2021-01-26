package com.zx.arch.socket;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * @author lizx
 * @since 1.0.0
 * @description 模拟服务器
 * @note  使用socket模拟上传下载 https://blog.csdn.net/yxmaomao1991/article/details/50550516
 **/
public class Server {
    public static void main(String[] args) throws IOException, InterruptedException {
        ServerSocket serverSocket=new ServerSocket(8888);
        Socket socket=serverSocket.accept();
        OutputStream os=socket.getOutputStream();
        InputStream is=socket.getInputStream();
        byte[] bytes=new byte[1024];
        is.read(bytes);
        System.out.println(new String(bytes));
        Thread.sleep(3000);
        os.write("客户端你好".getBytes());
        Thread.sleep(6000);
        os.write("客户端你好".getBytes());
        socket.close();
        serverSocket.close();
    }
}
