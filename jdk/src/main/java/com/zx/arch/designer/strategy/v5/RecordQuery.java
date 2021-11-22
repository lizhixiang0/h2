package com.zx.arch.designer.strategy.v5;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/***************************************
 * @author:Alex Wang
 * @Date:2017/10/22
 * 532500648
 ***************************************/
public class RecordQuery
{

    private final Connection connection;

    public RecordQuery(Connection connection)
    {
        this.connection = connection;
    }

    /**
     *
     * @param handler   功能接口，根据不同的策略，传入不同的实现类
     * @param sql
     * @param params
     * @param <T>
     * @return
     * @throws SQLException
     */
    public <T> T query(RowHandler<T> handler, String sql, Object... params)
            throws SQLException
    {
        try (PreparedStatement stmt = connection.prepareStatement(sql))
        {
            int index = 1;
            for (Object param : params)
            {
                stmt.setObject(index++, param);
            }

            ResultSet resultSet = stmt.executeQuery();
            // query方法只负责将数据查出来,然后调用RowHandler进行数据封装，至于封装成什么结构，就看怎么处理！
            // 有两个优点：一是将查询和封装数据分开,符合单一职责；二是query主需要负责查询数据，扩展只需要在RowHandler中，很方便
            return handler.handle(resultSet);
        }
    }

}
