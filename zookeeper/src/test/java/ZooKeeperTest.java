import org.apache.zookeeper.*;
import org.apache.zookeeper.data.Stat;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class ZooKeeperTest {
    private ZooKeeper zkClient = null;

    @Before
    public void init() throws Exception {
        // 访问的IP:PORT，必须是多个，逗号隔开
        String connectString = "localhost:2182,127.0.0.1:2183,127.0.0.1:2184";
        // 会话时间
        int sessionTimeout = 1000;
        // 第三个参数是监听器 Watcher ,里面定义收到事件通知后执行的函数
        zkClient = new ZooKeeper(connectString, sessionTimeout, new Watcher() {
            @Override
            // 收到事件通知后的回调函数（用户的业务逻辑）
            public void process(WatchedEvent event) {
                /*System.out.println(event.getType() + "--" + event.getPath());

                // 再次启动监听
                try {
                    List<String> children = zkClient.getChildren("/", true);
                    for (String child : children) {
                        System.out.println(child);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }*/
            }
        });
    }

    // 创建子节点
    @Test
    public void create() throws Exception {
        // 参数 1：要创建的节点的路径；
        // 参数 2：节点数据 ；
        // 参数 3：节点权限 ；
        // 参数 4：节点的类型
        String nodeCreated = zkClient.create("/root", "root".getBytes(), ZooDefs.Ids.OPEN_ACL_UNSAFE, CreateMode.PERSISTENT);

        System.out.println(nodeCreated);
    }

    // 获取子节点
    @Test
    public void getChildren() throws Exception {
        List<String> children = zkClient.getChildren("/", true);
        for (String child : children) {
            System.out.println(child);
        }

        // 延时阻塞
        Thread.sleep(Long.MAX_VALUE);
    }

    // 判断 znode 是否存在
    @Test
    public void exist() throws Exception {
        Stat stat = zkClient.exists("/eclipse", false);
        System.out.println(stat == null ? "not exist" : "exist");
    }


}