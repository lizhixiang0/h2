package lang.object;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.*;

/**
 * @author lizx
 * @date 2021/8/17
 * @test  1、Object类本身是没有实现Cloneable接口的,所以直接调用clone()会报错！
 *        2、为了保证克隆出的对象和原对象不具备联系,需要将原对象中的引用变量全部重新拷贝
 *           换句话说就是原生的clone方法是浅拷贝,我们得把他改写成深拷贝，所以注意，以后如果要用到clone方法，必须改写！
 *     Typically, this means copying any mutable objects that comprise 构成 the internal "deep structure" of the object being cloned and replacing the references to these objects with references to the copies
 *      通常，这意味着复制构成被克隆对象的内部“深层结构”的任何可变对象，并用对副本的引用替换对这些对象的引用
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
        // 斩断与原对象的羁绊
        ArrayList<CloneTest> cloneTest = clone.getCloneTest();
        if (Objects.nonNull(cloneTest)){
            //clone.setCloneTest((ArrayList<CloneTest>) cloneTest.clone()); // 这样还是浅拷贝,针对集合容器的深拷贝通常有两种办法
            // 一种是利用序列化。一种是循环遍历手动拷贝如下
            ArrayList<CloneTest> newList = new ArrayList<>();
            for (CloneTest cloneTest1:cloneTest){
                newList.add((CloneTest) cloneTest1.clone());
            }
            clone.setCloneTest(newList);
        }
        return clone;
    }

    public static void main(String[] args) throws CloneNotSupportedException {
        CloneTest clone = new CloneTest("测试");
        CloneTest clone_inner = new CloneTest("拷贝");
        ArrayList<CloneTest> objects = new ArrayList<>();
        objects.add(clone_inner);
        clone.setCloneTest(objects);
        CloneTest newCloneTest = (CloneTest)clone.clone();

        clone_inner.setTest("改写后2");// 改变原对象的引用变量会影响到拷贝变量
        clone.setTest("改写后1");// 改变原对象的基本变量不会影响到拷贝变量

        System.out.println(clone);
        System.out.println(newCloneTest);
    }
}
