/*
 * Copyright (c) 2010, 2013, Oracle and/or its affiliates. All rights reserved.
 * ORACLE PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */
package java.util.function;

import java.util.Objects;

/**
 * This is a functional interface whose functional method is accept(Object).
 * 这是一个函数接口，其函数方法是accept(Object)。
 *
 * Represents an operation that accepts a single input argument and returns no result.
 * 表示接受单个输入参数而不返回结果的操作。
 *
 * Unlike most other functional interfaces, Consumer is expected to operate via side-effects.
 * 与大多数其他功能接口不同，消费者将通过附作用进行操作。 附作用解释：https://blog.csdn.net/ustcyy91/article/details/80374401
 *
 * @param <T> the type of the input to the operation
 *
 * @since 1.8
 */
@FunctionalInterface
public interface Consumer<T> {

    /**
     * Performs this operation on the given argument.
     *
     * @param t the input argument
     */
    void accept(T t);

    /**
     * Returns a composed Consumer that performs, in sequence, this operation followed by the  after operation.
     * 返回一个组合的Consumer，它依次执行此操作和after操作
     *
     * If performing either operation throws an exception, it is relayed to the caller of the composed operation.
     * If performing this operation throws an exception,the after operation will not be performed.
     *
     * @param after the operation to perform after this operation
     * @return a composed Consumer that performs in sequence this operation followed by the after operation
     * @throws NullPointerException if after is null
     */
    default Consumer<T> andThen(Consumer<? super T> after) {
        Objects.requireNonNull(after);
        return (T t) -> {
            accept(t);
            after.accept(t);
        };
    }
}
