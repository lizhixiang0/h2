package com.zx.arch.guava.BasicUtilities;

import com.google.common.base.Optional;
import com.google.common.collect.Maps;

import java.util.HashMap;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class OptionalTest {
    private static HashMap map = Maps.newHashMap();

    private static boolean a() {
        Optional<Integer> possible = Optional.of(null);
        return possible.isPresent();
    }

    public static void main(String[] args) {

        map.put(null, "a");
        System.out.println(map.get("a"));

        map.put("a", null);
        System.out.println(map.get("a"));
        // Null�ĺ����������˺ܲ������Null���ٿ�����ȷ�ر�ʾĳ������
        // ���磬Map.get(key)����Nullʱ�����ܱ�ʾmap�е�ֵ��null�����map��û��key��Ӧ��ֵ��
        // Null���Ա�ʾʧ�ܡ��ɹ��򼸺��κ����

    }
}
