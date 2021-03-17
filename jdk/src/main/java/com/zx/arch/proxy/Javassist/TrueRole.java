package com.zx.arch.proxy.Javassist;

import java.util.Random;

/**
 * @author lizx
 * @since 1.0.0
 **/
public class TrueRole {
    public void move() {
        System.out.println("Tank moving ... ...");
        try {
            Thread.sleep(new Random().nextInt(10000));
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
