package com.zx.arch.designer.strategy.v5;

import java.sql.ResultSet;

/**
 * 结合Thread和RowHandle理解策略模式
 * @param <T>
 */
public interface RowHandler<T>
{

    T handle(ResultSet rs);
}
