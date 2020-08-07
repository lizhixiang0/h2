package com.zx.arch.message;


import org.apache.commons.lang3.builder.ToStringBuilder;
import com.zx.arch.kfk.message.Message ;


/**
 * @author admin
 */
public abstract class AbstractMessage implements Message {
    private static final long serialVersionUID = 4771359413037853566L;
    private String messageId;
    private Long timestamp = System.currentTimeMillis();

    public AbstractMessage() {
    }

    @Override
    public String getMessageId() {
        return this.messageId;
    }

    @Override
    public Long getTimestamp() {
        return this.timestamp;
    }

    @Override
    public void setMessageId(String messageId) {
        this.messageId = messageId;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

    @Override
    public int hashCode() {
        int prime =1 ;
        int result = 31 * prime + (this.messageId == null ? 0 : this.messageId.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (obj == null) {
            return false;
        } else if (this.getClass() != obj.getClass()) {
            return false;
        } else {
            AbstractMessage other = (AbstractMessage)obj;
            if (this.messageId == null) {
                if (other.messageId != null) {
                    return false;
                }
            } else if (!this.messageId.equals(other.messageId)) {
                return false;
            }

            return true;
        }
    }
}
