package lang.thread.v1;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class ThreadDemoV1 {
    private static void test(){
        new Thread(()->{
            System.out.println("ss");
        }).start();
    }

    public static void main(String[] args) {
        test();
    }
}
