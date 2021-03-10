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
 * @description ��װ��zookeeperԭװ��api ,�ҽ��һ��������,�ȶ��Ա�ԭװ�ĺ�̫����
 **/
public class CuratorFrameworkTest {

    private RetryPolicy retryPolicy = new ExponentialBackoffRetry(1000, 1);

    private CuratorFramework client;
    /**
     * root���ڵ���һֱ���ڵģ�������浽root��,�Լ�����¯���Ǿͱ�����ȴ������ڵ�
     */
    private static final String PATH = "/root/demoZK/test";

    @Before
    public void init() {
        String connectString = "localhost:2182,localhost:2183,localhost:2184";
        // �Ự��ʱʱ��
        int sessionTimeoutMs = 20000;
        // ���ӳ�ʱʱ��
        int connectionTimeoutMs = 5000;
        client = CuratorFrameworkFactory.newClient(connectString, sessionTimeoutMs, connectionTimeoutMs, retryPolicy);
        client.start();
    }

    // �����ӽڵ�
    @Test
    public void create() throws Exception {
        String s = client.create()
                // �־á�����
                .withMode(CreateMode.PERSISTENT_SEQUENTIAL)
                .withACL(ZooDefs.Ids.OPEN_ACL_UNSAFE)
                .forPath(PATH, "WTF".getBytes());
        System.out.println(s);
    }

    // ��ȡ�ڵ�����
    @Test
    public void getData() throws Exception {
        // 1����ͨ��ѯ
        byte[] bytes = client.getData().forPath(PATH);
        System.out.println(new String(bytes));
        // 2������״̬��ѯ
        Stat stat = new Stat();
        stat.setVersion(1);
        byte[] bytes1 = client.getData().storingStatIn(stat).forPath(PATH);
        System.out.println(new String(bytes1));
    }

    // ���½ڵ�����
    // @blog https://www.jianshu.com/p/546eab9143da
    @Test
    public void updateData() throws Exception {
        // set֮ǰҪ��汾�Աȡ���-1������ڽ���ʱ�㲻��ȥ�Ա���
        client.setData().withVersion(-1).forPath(PATH,"xin".getBytes());
        // ��ͨ����,��Ҫ��汾�Ա�
        client.setData().forPath(PATH,"xin nei".getBytes());

    }



    // �ж� /root/demoZK/test �Ƿ����,����ӡ�����ݰ汾��,����汾��������ֵ�ǿ���������֤
    @Test
    public void exist() throws Exception {
        // �жϽڵ��Ƿ����,�����������Ϊnull
        Stat stat = client.checkExists().forPath(PATH);
        System.out.println(Optional.of(stat).get().getVersion());
    }


    // ��ȡ�ӽڵ�
    @Test
    public void getChildren() throws Exception {
        List<String> children = client.getChildren().forPath("/root/demoZK");
        for (String child : children) {
            System.out.println(child);
        }
    }

    /**
     * Ϊ�ڵ�ע������¼�
     * @blog "https://www.jianshu.com/p/b789d7d6b3b2
     */
    public void watch(){}

}
