package util.interfaces.function;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.function.Consumer;

/**
 * @author lizx
 * @date 2021/9/16
 * @since
 * @description   了解Consumer的用法,暂时不知道他的优势是啥，以后补上！或许这玩意儿没啥优势，他就是个标识新的接口，特点是可以对对象进行改变，没有返回值！
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
        // 超过18岁转变成女孩,变成女孩后狂怒
        ConsumerTest consumerTest = new ConsumerTest(19,"consumer",false);

//       1、最low操作,面向过程
//        if (consumerTest.getAge()> SEX_LIMIT){
//            consumerTest.setGirl(true);
//            System.out.println("wow!");
//            consumerTest.shout();
//
//        }
//         2、封装成方法
//        update1(consumerTest);

        // 3、使用Consumer,将方法封装到函数对象里
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
        // 4、封装成方法
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
        // // 先执行accept的方法，再执行andThen的方法。如果有多个andThen，按从左到右依次执行andThen
        consumer.andThen(thenConsumer).accept(consumerTest);
    }

    public static void main(String[] args) {
        new ConsumerTest().test01();
    }
}
