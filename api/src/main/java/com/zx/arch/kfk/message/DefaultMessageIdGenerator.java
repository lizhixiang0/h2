package com.zx.arch.kfk.message;

import java.util.UUID;

/**
 * @author lizx
 * @date 2020/07/20
 **/
public class DefaultMessageIdGenerator implements MessageIdGenerator {
    public DefaultMessageIdGenerator() {
    }

    @Override
    public String generator() {
        return UUID.randomUUID().toString();
    }
}
