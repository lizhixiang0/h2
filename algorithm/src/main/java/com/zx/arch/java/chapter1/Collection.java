package com.zx.arch.java.chapter1;

/**
 * @author lizx
 * @since 1.0.0
 * @description 设计一个泛型类Collection，它存储object对象的集合（在数组中），以及该集合当前的大小。
 *   提供public方法isEmpty、makeEmpty、insert、remove、isPresent.
 *   方法isPresent(x)当且仅当在集合中存在（由equals定义） 等于x的一个object时返回true
 **/
public class Collection<T> {
    // 1、存储object对象的集合（在数组中）
    T[] objects ;
    // 2、集合当前的大小
    Long size;

    public Collection() {
        objects = (T[]) new Object[16];
    }

    public Collection(int capacity) {
        objects = (T[]) new Object[capacity];
    }

    public Boolean isEmpty(){
        if (objects==null || objects.length<1 || size<=0L){
            return Boolean.TRUE;
        }else {
            return Boolean.FALSE;
        }
    }

    public void makeEmpty(){
        if(objects!=null){
            objects=null;
            size = 0L;
        }
    }

    public void insert(T t){
        if(objects!=null&& objects[objects.length-1]!=null){

        }
    }





}
