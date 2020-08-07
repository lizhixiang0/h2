package com.zx.arch.handle;

import com.zx.arch.exception.BusinessException;
import com.zx.arch.exception.RetryableBusinessException;
import com.zx.arch.exception.ServiceException;
import com.zx.arch.kfk.message.Message;
import com.zx.arch.utils.RetryUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.ConcurrencyFailureException;

import java.time.Duration;
import java.time.Instant;

/**
 * @author admin
 */
public abstract class AbstractHandler<T extends Message> {
    protected static final int MAX_PUSH_TERMINALS = 1000;
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());
    protected static final int DEFAULT_RETRY_TIMES = 3;
    protected static final int MAX_RETRY_TIMES = 5;
    private int retryTimes = 3;

    public AbstractHandler() {
    }

    public final void handleMessage(T message) {
        Instant start = null;
        if (this.logger.isDebugEnabled()) {
            this.logger.debug(">>>> Received message [{}]", message);
            start = Instant.now();
        }

        try {
            RetryUtils.retry(() -> {
                this.handleInternal(message);
                return null;
            }, (e) -> {
                return this.isExceptionShouldRetry(e, message);
            }, this.retryTimes);
        } catch (ServiceException | BusinessException var4) {
            this.logger.warn("Unhandled BusinessException occurred, consumer ignored, message: [{}], error: [{}]", message, var4.toString());
        } catch (Throwable var5) {
            this.logger.error("Unhandled Exception occurred, consumer ignored, message details: [{}]", message, var5);
        }

        if (this.logger.isDebugEnabled()) {
            this.logger.debug(">>>> Processed message [{}], total time spend: [{}ms]", message, Duration.between(start, Instant.now()).toMillis());
        }

    }

    protected abstract void handleInternal(T message);

    protected void setRetryTimes(int retryTimes) {
        if (retryTimes >= 0 && retryTimes <= 5) {
            this.retryTimes = retryTimes;
        } else {
            this.logger.warn("Invalid retry times {} set, set to default {}", retryTimes, 3);
        }

    }

    protected boolean isExceptionShouldRetry(Throwable e, T message) {
        if (e == null) {
            return false;
        } else if (!(e instanceof ConcurrencyFailureException) && !(e instanceof RetryableBusinessException)) {
            return false;
        } else {
            this.logger.warn("{} occurred, will retry, message: {}", e.getClass().getName(), message);
            return true;
        }
    }
}
