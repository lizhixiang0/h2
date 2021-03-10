import org.apache.curator.RetryPolicy;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.ExponentialBackoffRetry;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.data.Stat;
import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.Optional;

/**
 * @author lizx
 * @since 1.0.0
 * @description 封装了zookeeper原装的api ,且解决一部分问题,稳定性比原装的好太多了
 **/
public class CuratorFrameworkTest {

    private RetryPolicy retryPolicy = new ExponentialBackoffRetry(1000, 1);

    private CuratorFramework client;
    /**
     * root根节点是一直存在的，如果不存到root里,自己另启炉灶那就必须得先创建根节点
     */
    private static final String PATH = "/root/demoZK/test";

    @Before
    public void init() {
        String connectString = "localhost:2182,localhost:2183,localhost:2184";
        // 会话超时时间
        int sessionTimeoutMs = 20000;
        // 连接超时时间
        int connectionTimeoutMs = 5000;
        client = CuratorFrameworkFactory.newClient(connectString, sessionTimeoutMs, connectionTimeoutMs, retryPolicy);
        client.start();
    }

    // 创建子节点
    @Test
    public void create() throws Exception {
        String s = client.create()
                // 持久、有序
                .withMode(CreateMode.PERSISTENT_SEQUENTIAL)
                .withACL(ZooDefs.Ids.OPEN_ACL_UNSAFE)
                .forPath(PATH, "WTF".getBytes());
        System.out.println(s);
    }

    // 获取节点内容
    @Test
    public void getData() throws Exception {
        // 1、普通查询
        byte[] bytes = client.getData().forPath(PATH);
        System.out.println(new String(bytes));
        // 2、包含状态查询
        Stat stat = new Stat();
        stat.setVersion(1);
        byte[] bytes1 = client.getData().storingStatIn(stat).forPath(PATH);
        System.out.println(new String(bytes1));
    }

    // 更新节点内容
    // @blog https://www.jianshu.com/p/546eab9143da
    @Test
    public void updateData() throws Exception {
        // set之前要求版本对比。填-1服务端在接收时便不会去对比了
        client.setData().withVersion(-1).forPath(PATH,"xin".getBytes());
        // 普通更新,不要求版本对比
        client.setData().forPath(PATH,"xin nei".getBytes());

    }



    // 判断 /root/demoZK/test 是否存在,并打印其数据版本号,这个版本号在设置值是可以用来验证
    @Test
    public void exist() throws Exception {
        // 判断节点是否存在,如果不存在则为null
        Stat stat = client.checkExists().forPath(PATH);
        System.out.println(Optional.of(stat).get().getVersion());
    }


    // 获取子节点
    @Test
    public void getChildren() throws Exception {
        List<String> children = client.getChildren().forPath("/root/demoZK");
        for (String child : children) {
            System.out.println(child);
        }
    }

    /**
     * 为节点注册监听事件
     * @blog "https://www.jianshu.com/p/b789d7d6b3b2
     */
    public void watch(){}

}
