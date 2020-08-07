package com.zx.arch.message;

import com.zx.arch.message.MessageIdGenerator;

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
