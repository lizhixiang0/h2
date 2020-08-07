package com.zx.arch.utils;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.base.Throwables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ThreadLocalRandom;

public class RetryUtils {
    public static final Logger log = LoggerFactory.getLogger(RetryUtils.class);

    private RetryUtils() {
    }

    public static <T> T retry(final Callable<T> f, Predicate<Throwable> shouldRetry, final Runnable op, final int quietTries, final int maxTries) throws Exception {
        Preconditions.checkArgument(maxTries > 0, "maxTries > 0");
        byte nTry = 0;

        while(true) {
            try {
                int var8 = nTry + 1;
                return f.call();
            } catch (Throwable var7) {
                if (nTry >= maxTries || !shouldRetry.apply(var7)) {
                    Throwables.throwIfInstanceOf(var7, Exception.class);
                    throw var7;
                }

                Optional.ofNullable(op).ifPresent((c) -> {
                    try {
                        op.run();
                    } catch (Exception var3) {
                        log.warn("Failed to execute exception handler", var3);
                    }

                });
                awaitNextRetry(var7, nTry, nTry <= quietTries);
            }
        }
    }

    public static <T> T retry(final Callable<T> f, Predicate<Throwable> shouldRetry, final int maxTries) throws Exception {
        return retry(f, shouldRetry, (Runnable)null, 0, maxTries);
    }

    public static <T> T retry(final Callable<T> f, Predicate<Throwable> shouldRetry, final Runnable ec, final int maxTries) throws Exception {
        return retry(f, shouldRetry, ec, 0, maxTries);
    }

    private static void awaitNextRetry(final Throwable e, final int nTry, final boolean quiet) throws InterruptedException {
        long sleepMillis = nextRetrySleepMillis(nTry);
        if (quiet) {
            log.debug("Failed on try {}, retrying in {},dms.", new Object[]{nTry, sleepMillis, e});
        } else {
            log.warn("Failed on try {}, retrying in {},dms.", new Object[]{nTry, sleepMillis, e});
        }

        Thread.sleep(sleepMillis);
    }

    private static long nextRetrySleepMillis(final int nTry) {
        long baseSleepMillis = 1000L;
        long maxSleepMillis = 60000L;
        double fuzzyMultiplier = Math.min(Math.max(1.0D + 0.2D * ThreadLocalRandom.current().nextGaussian(), 0.0D), 2.0D);
        return (long)(Math.min(60000.0D, 1000.0D * Math.pow(2.0D, (double)(nTry - 1))) * fuzzyMultiplier);
    }
}
