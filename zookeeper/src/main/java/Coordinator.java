import org.apache.zookeeper.ZooKeeper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
/**
 * @author lizx
 * @since 1.0.0
 **/
public class Coordinator {
    private final static String PARENT_NODE = "/engines";

    private ArrayList<String> servers;

    private ZooKeeper zkClient = null;

    /**
     * 创建到 zkClient 的客户端连接
     */
    public void getConnect() throws IOException {
        String connectString = "127.0.0.1:2181";
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
        // 2、创建一个新的集合，存放当前还健在的服务
        servers = new ArrayList<>();
        // 3 遍历所有节点，获取节点中的主机名称信息放到集合中
        for (String child : children) {
            byte[] data = zkClient.getData(PARENT_NODE + "/" + child, false, null);
            servers.add(new String(data));
        }
    }

    /**
     * 业务功能,从servers集合中获取健在的服务器
     */
    public void business() throws InterruptedException {
        while(true){
            Thread.sleep(2000);
            if(!servers.isEmpty()){
                System.out.println(String.format("%s is working ...", servers.get(0)));
            }else {
                System.out.println("down ...");
                break;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        Coordinator client = new Coordinator();
        // 1 获取 zk 连接
        client.getConnect();
        // 2 获取 servers 的子节点信息，从中获取服务器信息列表
        client.getServerList();
        // 3 业务进程启动
        client.business();
    }
}
