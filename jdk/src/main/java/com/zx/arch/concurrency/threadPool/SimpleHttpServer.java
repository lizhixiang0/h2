package com.zx.arch.concurrency.threadPool;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * @author admin
 */
public class SimpleHttpServer {
    // ����HttpRequest���̳߳�
    static ThreadPool<HttpRequestHandler> threadPool = new DefaultThreadPool<>(11);
    // SimpleHttpServer�ĸ�·��
    static String                         basePath;
    static ServerSocket                   serverSocket;
    // ��������˿�
    static int                            port       = 8081;

    public static void setPort(int port) {
        if (port > 0) {
            SimpleHttpServer.port = port;
        }
    }

    public static void setBasePath(String basePath) {
        if (basePath != null && new File(basePath).exists() && new File(basePath).isDirectory()) {
            SimpleHttpServer.basePath = basePath;
        }
    }

    public static void main(String[] args) throws Exception {
        SimpleHttpServer.setBasePath("D:\\JetBrains\\workspace\\h2\\jdk\\src\\main\\java\\com\\zx\\arch\\concurrency\\threadPool");
        SimpleHttpServer.start();
    }

    // ����SimpleHttpServer
    public static void start() throws Exception {
        serverSocket = new ServerSocket(port);
        Socket socket = null;
        while ((socket = serverSocket.accept()) != null) {
            // ����һ���ͻ���Socket������һ��HttpRequestHandler�������̳߳�ִ��
            threadPool.execute(new HttpRequestHandler(socket));
        }
        serverSocket.close();
    }

    static class HttpRequestHandler implements Runnable {

        private Socket socket;

        public HttpRequestHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            String line = null;
            BufferedReader br = null;
            BufferedReader reader = null;
            PrintWriter out = null;
            InputStream in = null;
            try {
                reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String header = reader.readLine();
                // �����·�����������·��
                String filePath = basePath + header.split(" ")[1];
                out = new PrintWriter(socket.getOutputStream());
                // ���������Դ�ĺ�׺Ϊjpg����ico�����ȡ��Դ�����
                if (filePath.endsWith("jpg") || filePath.endsWith("ico") || filePath.endsWith("png")) {
                    in = new FileInputStream(filePath);
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    int i = 0;
                    while ((i = in.read()) != -1) {
                        baos.write(i);
                    }

                    byte[] array = baos.toByteArray();
                    OutputStream outputStream = socket.getOutputStream();
//                    out.println("HTTP/1.1 200 OK");
//                    out.println("Content-Type: image/jpeg");
//                    out.println("Content-Length: " + array.length);
//                    out.println("");
                    outputStream.write("HTTP/1.1 200 OK".getBytes());
                    outputStream.write("Server: Molly".getBytes());
                    outputStream.write("Content-Type: image/jpeg".getBytes());
                    outputStream.write(("Content-Length: " + array.length).getBytes());
                    outputStream.write("\n\n".getBytes());
                    outputStream.write(array, 0, array.length);  // ͼƬ����Ӧ���ͷ�����ݶ��ñ���ֽ�������
                } else {
                    br = new BufferedReader(new InputStreamReader(new FileInputStream(filePath)));
                    out = new PrintWriter(socket.getOutputStream());
                    out.println("HTTP/1.1 200 OK");
                    out.println("Server: Molly");
                    out.println("Content-Type: text/html; charset=UTF-8");

                    out.println("");
                    while ((line = br.readLine()) != null) {
                        out.println(line);
                    }
                }
                out.flush();
            } catch (Exception ex) {
                out.println("HTTP/1.1 500");
                out.println("Content-Type: text/html; charset=UTF-8");
                out.flush();
            } finally {
                close(br, in, reader, out, socket);
            }
        }
    }

    // �ر�������Socket
    private static void close(Closeable... closeables) {
        if (closeables != null) {
            for (Closeable closeable : closeables) {
                try {
                    closeable.close();
                } catch (Exception ex) {
                    // ����
                }
            }
        }
    }
}
