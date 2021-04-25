package com.zx.arch.jdk;

import lombok.Data;
import ognl.OgnlContext;
import ognl.OgnlRuntime;
import ognl.PropertyAccessor;

import java.util.HashMap;
import java.util.Map;

/**
 * @author lizx
 * @since 1.0.0
 * @description  对象导航图语言（Object Graph Navigation Language），简称OGNL，是应用于Java中的一个开源的表达式语言
 * @descrpiton mybatis中用到的，这里做个简单的测试
 **/
public class OnglTest {

    static {
        OgnlRuntime.setPropertyAccessor(Person.class,new ContextAccessor());
    }

    public static void main(String[] args) {
        Person person = new Person();
        System.out.println(person.get("ss"));
    }

    @Data
    static
    class Person extends HashMap<String, Object> {
        @Override
        public Object get(Object key) {
            return super.get(key);
        }
        private String name;
    }

    static class ContextAccessor implements PropertyAccessor {

        @Override
        public Object getProperty(Map context, Object target, Object name) {
            return "我是大傻逼";
        }

        @Override
        public void setProperty(Map context, Object target, Object name, Object value) {

        }

        @Override
        public String getSourceAccessor(OgnlContext context, Object target, Object index) {
            return null;
        }

        @Override
        public String getSourceSetter(OgnlContext context, Object target, Object index) {
            return null;
        }
    }
}



