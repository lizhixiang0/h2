package util.list;


import java.util.ArrayList;
import java.util.Iterator;

/**
 * @author lizx
 * @date 2021/8/19
 * @since
 **/
public class ArrayListTest {

    /**
     * �����ڲ���Itr
     */
    public void testIter(){
        // �����ڲ��ഴ������,��˼�Ǵ�����һ��ArrayList������,Ȼ����������ഴ������,�鿴�ֽ�����Է��ֶ��������һ��class�ļ�,�Ǹ��ļ�����������
        ArrayList array = new ArrayList<String>(){

            // ���Զ������Ի򷽷�
            private String name  = "Objects created by anonymous inner classes";

            public String getName(){return name;}

            // ��������,���Զ��ϲ������캯����
            {
                add("aaa");
                add("bbb");
                add("ccc");
                add("ddd");
            }
        };

        // ����,�������

        Iterator iterator = array.iterator();


    }

    public static void main(String[] args) {
        new ArrayListTest().testIter();
    }
}
