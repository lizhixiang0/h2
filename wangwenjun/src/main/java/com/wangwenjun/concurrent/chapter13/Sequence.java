package com.wangwenjun.concurrent.chapter13;

import javax.naming.Context;


/**
 * volatile禁止重排序，这个程序就是模拟一下
 * @author admin
 */
public class Sequence {

    private boolean initialized = false;

    private Context context;

    public Context load(){
        if(!initialized){
            loadContext();
            initialized = true;
        }

        return context;
    }

    public void loadContext(){}

}
