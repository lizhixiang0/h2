package com.zx.arch.guava.collections;

import com.google.common.collect.HashMultiset;
import com.google.common.collect.Multiset;
import org.springframework.core.NamedInheritableThreadLocal;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @author lizx
 * @since 1.0.0
 * @blog "http://ifeve.com/google-guava-newcollectiontypes/
 *       "https://www.cnblogs.com/peida/p/Guava_Multiset.html
 * @description  Guava������JDK��û�еģ����Ƿǳ����õ�һЩ�µļ�������
 *
 *      Guava�ж�����¼����У�
 * ����                       Multiset
 * ����                       SortedMultiset
 * ����                       Multimap
 * ����                       ListMultimap
 * ����                       SetMultimap
 * ����                       BiMap
 * ����                       ClassToInstanceMap
 * ����                       Table
 **/
public class MultisetTest {
    private static  String[] words = {"a","a","a","c","c"};

    /**
     * ͳ��һ�������ĵ��г����˶��ٴΣ���ͳ����������
     * ȱ�㣺��֧��ͬʱ�ռ�����ͳ����Ϣ�����ܴ���
     */
    public static void a(){
        Map<String, Integer> counts = new HashMap<>(16);
        for (String word : words) {
            Integer count = counts.get(word);
            if (count == null) {
                counts.put(word, 1);
            } else {
                counts.put(word, count + 1);
            }
        }
    }

    /**
     * Guava�ṩ��һ���¼������� Multiset
     * �ص�: Multisetռ����List��Set֮���һ����ɫ�ش��������ظ������ǲ���֤˳��
     * ע��: Multiset�̳���JDK�е�Collection�ӿڣ�������Set�ӿ�,��Ҫ��������
     * ������
     *      add(E)��ӵ�������Ԫ��
     *      iterator()����һ��������������Multiset������Ԫ�أ������ظ���Ԫ�أ�
     *      size()��������Ԫ�ص��ܸ����������ظ���Ԫ�أ�
     *
     *      count(Object)���ظ���Ԫ�صļ�����
     *      entrySet()����Set<Multiset.Entry<E>>����Map��entrySet���ơ�
     *      elementSet()�������в��ظ�Ԫ�ص�Set<E>����Map��keySet()���ơ�
     *
     *      remove(E, int)	���ٸ���Ԫ����Multiset�еļ���
     *      setCount(E, int)	���ø���Ԫ����Multiset�еļ�����������Ϊ����
     */
    public static void b(){
        Multiset<String> stringMultiset = HashMultiset.create();
        stringMultiset.addAll(Arrays.asList(words));
        System.out.println("����words��Ԫ�ص��ܸ���:"+stringMultiset.size());
        System.out.println("����Ԫ��a���ܸ���:"+stringMultiset.count("a"));
        System.out.println("��������Ԫ��(ȥ��):"+stringMultiset.elementSet().toString());
    }

    public static void main(String[] args) {
        b();
    }
}
