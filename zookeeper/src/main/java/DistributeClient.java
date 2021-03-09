import org.apache.zookeeper.ZooKeeper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class DistributeClient {
    private final static String PARENT_NODE = "/servers";

    private ZooKeeper zkClient = null;

    /**
     * 创建到 zkClient 的客户端连接
     */
    public void getConnect() throws IOException {
        String connectString = "127.0.0.1:2182,127.0.0.1:2183,127.0.0.1:2184";
        int sessionTimeout = 2000;
        zkClient = new ZooKeeper(connectString, sessionTimeout, event -> {
            // 再次启动监听
            try {
                getServerList();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    /**
     * 获取服务器列表信息
     */
    public void getServerList() throws Exception {
        // 1 获取服务器子节点信息，并且对父节点进行监听
        List<String> children = zkClient.getChildren(PARENT_NODE, true);
        // 2 存储服务器信息列表
        ArrayList<String> servers = new ArrayList<>();
        // 3 遍历所有节点，获取节点中的主机名称信息
        for (String child : children) {
            byte[] data = zkClient.getData(PARENT_NODE + "/" + child, false, null);
            servers.add(new String(data));
        }
        // 4 打印服务器列表信息
        System.out.println(servers);
    }

    /**
     * 业务功能
     */
    public void business() throws Exception {
        System.out.println("client is working ...");
        Thread.sleep(Long.MAX_VALUE);
    }

    public static void main(String[] args) throws Exception {
        DistributeClient client = new DistributeClient();
        // 1 获取 zk 连接
        client.getConnect();
        // 2 获取 servers 的子节点信息，从中获取服务器信息列表
        client.getServerList();
        // 3 业务进程启动
        client.business();
    }
}
