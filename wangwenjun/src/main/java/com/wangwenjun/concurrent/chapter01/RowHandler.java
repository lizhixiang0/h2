package com.wangwenjun.concurrent.chapter01;

import java.sql.ResultSet;

/**
 * 结合Thread和RowHandle理解策略模式
 * @author admin
 * @param <T>
 */
public interface RowHandler<T> {
    T handle(ResultSet rs);
}
