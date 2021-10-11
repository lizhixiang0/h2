package util.concurrent.locks;

import java.util.concurrent.locks.LockSupport;

/**
 * @author lizx
 * @date 2021/10/11
 * @since
 * @description  LockSupport��һ���̹߳����࣬���еķ������Ǿ�̬�������������߳�������λ��������Ҳ����������λ�û���
 *               �е�����wait/notify,��������������
 *               1��wait��notify����Object�еķ���,�ڵ�������������ǰ�����Ȼ�������󣬵���park����Ҫ��ȡĳ���������
 *               2��notifyֻ�����ѡ��һ���̻߳��ѣ��޷�����ָ�����̣߳�unparkȴ���Ի���һ��ָ�����̡߳�
 *               3��������Ӧinterrupt�жϣ�wait���׳�һ���ж��쳣 InterruptedException��LockSupport�ǽ���park,�����׳��쳣
 * @blog 'https://baijiahao.baidu.com/s?id=1666548481761194849&wfr=spider&for=pc
 **/
public class LockSupportTest {
    public static class DemoThread extends Thread {
        @Override
        public void run() {
            System.out.println(getName() + "�����߳�");
            LockSupport.unpark(this); // park/unpark ʹ��ʱû���Ⱥ�˳��
            LockSupport.park();
            System.out.println(getName() + "�߳����н���");
        }
    }

    public static void main(String[] args) {
        DemoThread demoThread = new DemoThread();

        demoThread.start();
        System.out.println("demoThread�߳��Ѿ�����");

        System.out.println("���߳̽���");
        demoThread.interrupt();
    }
}
