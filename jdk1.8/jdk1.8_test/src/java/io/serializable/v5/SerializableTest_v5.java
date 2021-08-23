package io.serializable.v5;

import io.serializable.SerializableUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.ToString;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * @author lizx
 * @since 1.0.0
 * @description 我理解的java序列化有两个作用，一种是可以实现远程过程调用RPC，一种是做缓存
 **/
public class SerializableTest_v5 implements Serializable {

    /**
     * 测试点1、实现RPC,简单试试,具体的看博客,这边只是单纯传个对象
     *                  https://blog.csdn.net/weixin_38405253/article/details/101805188
     *                  https://blog.csdn.net/ss123mlk/article/details/108555850
     * @param args
     */
    public static void main(String[] args) throws IOException {
        new Thread(() -> {
            try {
                new Server().start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();

        new Client().connect();
    }


}

@Getter
@Setter
@ToString
class Person implements Serializable{

    private static final long serialVersionUID = 1L;

    private String name;
    private String age;

    public Person(String name, String age) {
        this.name = name;
        this.age = age;
    }
}

class Server{

    private static final int SERVER_PORT = 6000;

    private ServerSocket server;

    public Server() {
        try {
             server = new ServerSocket(SERVER_PORT);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void start() throws IOException {
        Socket socket = null;
        // 服务器会一直开着
        while (true) {
            try {
                synchronized (server) {
                    socket = server.accept();
                }
                socket.setSoTimeout(20000);
                process(socket);
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }finally {
                socket.close();
            }
        }
    }

    private void process(Socket socket) throws IOException, ClassNotFoundException {
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        Person data = (Person) in.readObject();
        System.out.println(data);
        in.close();
    }
}

class Client{
    private String address = "127.0.0.1";
    private int port = 6000;
    private Socket clientSocket;

    public Client() {
        clientSocket = new Socket();
    }

    public void  connect() throws IOException {
        try {
            clientSocket.connect(new InetSocketAddress(this.address, this.port), 10000);
            process();
        } catch (java.io.IOException e) {
            e.printStackTrace();
        }finally {
            clientSocket.close();

        }
    }

    public void process() throws IOException {
        ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
        Person person = new Person("阿祥","18");
        out.writeObject(person);
        out.flush();
        out.close();
    }
}







