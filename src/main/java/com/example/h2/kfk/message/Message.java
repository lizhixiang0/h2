package com.example.h2.kfk.message;

import java.io.Serializable;

/**
 * @author lizx
 * @date 2020/07/20
 **/
public interface Message extends Serializable {
    String getMessageId();

    void setMessageId(String messageId);

    Long getTimestamp();
}
