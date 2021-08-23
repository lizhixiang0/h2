package lang.object;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.*;

/**
 * @author lizx
 * @date 2021/8/17
 * @test  1��Object�౾����û��ʵ��Cloneable�ӿڵ�,����ֱ�ӵ���clone()�ᱨ��
 *        2��Ϊ�˱�֤��¡���Ķ����ԭ���󲻾߱���ϵ,��Ҫ��ԭ�����е����ñ���ȫ�����¿���
 *           ���仰˵����ԭ����clone������ǳ����,���ǵð�����д�����������ע�⣬�Ժ����Ҫ�õ�clone�����������д��
 *     Typically, this means copying any mutable objects that comprise ���� the internal "deep structure" of the object being cloned and replacing the references to these objects with references to the copies
 *      ͨ��������ζ�Ÿ��ƹ��ɱ���¡������ڲ������ṹ�����κοɱ���󣬲��öԸ����������滻����Щ���������
 * @since
 **/
@Setter
@Getter
@ToString
public class CloneTest implements Cloneable{
    private String test ;

    private ArrayList<CloneTest> cloneTest;

    public CloneTest(String test) {
        this.test = test;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        CloneTest clone = (CloneTest)super.clone();
        // ն����ԭ������
        ArrayList<CloneTest> cloneTest = clone.getCloneTest();
        if (Objects.nonNull(cloneTest)){
            //clone.setCloneTest((ArrayList<CloneTest>) cloneTest.clone()); // ��������ǳ����,��Լ������������ͨ�������ְ취
            // һ�����������л���һ����ѭ�������ֶ���������
            ArrayList<CloneTest> newList = new ArrayList<>();
            for (CloneTest cloneTest1:cloneTest){
                newList.add((CloneTest) cloneTest1.clone());
            }
            clone.setCloneTest(newList);
        }
        return clone;
    }

    public static void main(String[] args) throws CloneNotSupportedException {
        CloneTest clone = new CloneTest("����");
        CloneTest clone_inner = new CloneTest("����");
        ArrayList<CloneTest> objects = new ArrayList<>();
        objects.add(clone_inner);
        clone.setCloneTest(objects);
        CloneTest newCloneTest = (CloneTest)clone.clone();

        clone_inner.setTest("��д��2");// �ı�ԭ��������ñ�����Ӱ�쵽��������
        clone.setTest("��д��1");// �ı�ԭ����Ļ�����������Ӱ�쵽��������

        System.out.println(clone);
        System.out.println(newCloneTest);
    }
}
