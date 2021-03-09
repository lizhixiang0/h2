import org.apache.zookeeper.*;

import java.io.IOException;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class Engine {

    private final static String PARENT_NODE = "/servers";

    private ZooKeeper zkClient = null;

    /**
     * 创建到 zk 的客户端连接
     */
    public void getConnect() throws IOException {
        String connectString = "localhost:2182,localhost:2183,localhost:2184";
        int sessionTimeout = 10000;
        zkClient = new ZooKeeper(connectString, sessionTimeout, event -> {});
    }

    /**
     * 注册引擎
     */
    public void registerServer(String hostname) throws Exception {
        // 创建一个完全开放的临时有序节点 ,注意PARENT_NODE得提前创建,必须在父节点存在的时候 ，才能创建子节点。
        String create = zkClient.create(PARENT_NODE + "/server", hostname.getBytes(), ZooDefs.Ids.OPEN_ACL_UNSAFE,CreateMode.EPHEMERAL_SEQUENTIAL);
        System.out.println(hostname + " is online " + create);
    }

    /**
     * 业务功能
     */
    public void business() throws Exception {
        System.out.println("working ...");
        // 模拟服务端,工作20s后宕机
        Thread.sleep(20000L);
        System.out.println("down ...");
    }

    public static void main(String[] args) throws Exception {
        Engine server = new Engine();
        // 1 获取 zk 连接
        server.getConnect();
        // 2 服务一上线就利用 zk 注册当前服务器信息
        server.registerServer(System.getProperty("os.name"));
        // 3 注册完就去搞业务功能，不用再管了,所以这个注册行为可以放到启动类中
        server.business();
    }
}
