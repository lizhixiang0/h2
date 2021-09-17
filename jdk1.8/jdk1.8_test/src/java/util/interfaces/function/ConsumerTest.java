package util.interfaces.function;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.function.Consumer;

/**
 * @author lizx
 * @date 2021/9/16
 * @since
 * @description   �˽�Consumer���÷�,��ʱ��֪������������ɶ���Ժ��ϣ������������ûɶ���ƣ������Ǹ���ʶ�µĽӿڣ��ص��ǿ��ԶԶ�����иı䣬û�з���ֵ��
 **/
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ConsumerTest {

    public static final int SEX_LIMIT = 18;

    private int age;
    private String name;
    private boolean isGirl;

    public void shout(){
        System.out.println("what the fuck !");
    }

    public void test01(){
        // ����18��ת���Ů��,���Ů�����ŭ
        ConsumerTest consumerTest = new ConsumerTest(19,"consumer",false);

//       1����low����,�������
//        if (consumerTest.getAge()> SEX_LIMIT){
//            consumerTest.setGirl(true);
//            System.out.println("wow!");
//            consumerTest.shout();
//
//        }
//         2����װ�ɷ���
//        update1(consumerTest);

        // 3��ʹ��Consumer,��������װ������������
        Consumer<ConsumerTest> consumerTestConsumer1 = consumerTest1 -> {
            if (consumerTest1.getAge()> SEX_LIMIT){
                consumerTest1.setGirl(true);
                System.out.println("wow!");
            }
        };

        Consumer<ConsumerTest> consumerTestConsumer2 = consumerTest1 -> {
            consumerTest1.shout();
        };

        consumerTestConsumer1.andThen(consumerTestConsumer2).accept(consumerTest);
        // 4����װ�ɷ���
        update2(consumerTestConsumer1,consumerTestConsumer2,consumerTest);
    }

    public void update1(ConsumerTest consumerTest){
        if (consumerTest.getAge()> SEX_LIMIT){
            consumerTest.setGirl(true);
            System.out.println("wow!");
            consumerTest.shout();
        }
    }

    public void update2(Consumer<ConsumerTest> consumer,Consumer<ConsumerTest> thenConsumer,ConsumerTest consumerTest){
        // // ��ִ��accept�ķ�������ִ��andThen�ķ���������ж��andThen��������������ִ��andThen
        consumer.andThen(thenConsumer).accept(consumerTest);
    }

    public static void main(String[] args) {
        new ConsumerTest().test01();
    }
}
