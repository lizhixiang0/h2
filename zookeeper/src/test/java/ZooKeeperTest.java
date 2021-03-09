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
        // ���ʵ�IP:PORT�������Ƕ�������Ÿ���
        String connectString = "localhost:2182,127.0.0.1:2183,127.0.0.1:2184";
        // �Ựʱ��
        int sessionTimeout = 1000;
        // �����������Ǽ����� Watcher ,���涨���յ��¼�֪ͨ��ִ�еĺ���
        zkClient = new ZooKeeper(connectString, sessionTimeout, new Watcher() {
            @Override
            // �յ��¼�֪ͨ��Ļص��������û���ҵ���߼���
            public void process(WatchedEvent event) {
                /*System.out.println(event.getType() + "--" + event.getPath());

                // �ٴ���������
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

    // �����ӽڵ�
    @Test
    public void create() throws Exception {
        // ���� 1��Ҫ�����Ľڵ��·����
        // ���� 2���ڵ����� ��
        // ���� 3���ڵ�Ȩ�� ��
        // ���� 4���ڵ������
        String nodeCreated = zkClient.create("/root", "root".getBytes(), ZooDefs.Ids.OPEN_ACL_UNSAFE, CreateMode.PERSISTENT);

        System.out.println(nodeCreated);
    }

    // ��ȡ�ӽڵ�
    @Test
    public void getChildren() throws Exception {
        List<String> children = zkClient.getChildren("/", true);
        for (String child : children) {
            System.out.println(child);
        }

        // ��ʱ����
        Thread.sleep(Long.MAX_VALUE);
    }

    // �ж� znode �Ƿ����
    @Test
    public void exist() throws Exception {
        Stat stat = zkClient.exists("/eclipse", false);
        System.out.println(stat == null ? "not exist" : "exist");
    }


}