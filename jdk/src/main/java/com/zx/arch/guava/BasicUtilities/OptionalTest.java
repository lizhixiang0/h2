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
        // Null的含糊语义让人很不舒服。Null很少可以明确地表示某种语义
        // 例如，Map.get(key)返回Null时，可能表示map中的值是null，亦或map中没有key对应的值。
        // Null可以表示失败、成功或几乎任何情况

    }
}
