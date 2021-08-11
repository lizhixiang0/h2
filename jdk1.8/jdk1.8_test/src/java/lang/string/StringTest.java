package lang.string;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class StringTest {

    public static StringTest of(){
        return new StringTest();
    }
    public void atest(){
        String s1 = "123";
        System.out.println(s1.hashCode());
        s1 += " append";
        System.out.println(s1.hashCode());
        String s2 = "123 append";
        System.out.println(s2.hashCode());
        String s3 = "123 append";
        System.out.println(s3.hashCode());

        System.out.println(s1 == s2);
        System.out.println(s2 == s3);

    }

    public static void main(String[] args) {
        StringTest.of().atest();
    }
}
