import org.apache.zookeeper.*;

import java.io.IOException;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class DistributeServer {
    private ZooKeeper zkClient = null;

    /**
     * 创建到 zk 的客户端连接
     */
    public void getConnect() throws IOException {
        String connectString = "127.0.0.1:2182,127.0.0.1:2183,127.0.0.1:2184";
        int sessionTimeout = 2000;
        zkClient = new ZooKeeper(connectString, sessionTimeout, new Watcher() {
            @Override
            public void process(WatchedEvent event) {
            }
        });
    }

    /**
     * 注册服务器
     */
    public void registServer(String hostname) throws Exception {
        String parentNode = "/servers";
        String create = zkClient.create(parentNode + "/server", hostname.getBytes(), ZooDefs.Ids.OPEN_ACL_UNSAFE,
                CreateMode.EPHEMERAL_SEQUENTIAL);
        System.out.println(hostname + " is online " + create);
    }

    /**
     * 业务功能
     */
    public void business(String hostname) throws Exception {
        System.out.println(hostname + " is working ...");
        Thread.sleep(Long.MAX_VALUE);
    }

    public static void main(String[] args) throws Exception {
        // 1 获取 zk 连接
        DistributeServer server = new DistributeServer();
        server.getConnect();
        // 2 利用 zk 连接注册服务器信息
        server.registServer(args[0]);
        // 3 启动业务功能
        server.business(args[0]);
    }
}
