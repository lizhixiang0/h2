package com.mybatis.lizx;

import org.junit.Test;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * @author lizx
 * @since 1.0.0
 * @description 测试简单的jdbc代码
 **/
public class JdbcTest {
    @Test
    public void test() throws SQLException, ClassNotFoundException {
        Class.forName("com.mysql.cj.jdbc.Driver") ;
        String url = "jdbc:mysql://localhost:3306/db_mybatis?serverTimezone=GMT%2B8" ;
        String username = "root" ;
        String password = "root" ;
        Connection connection = DriverManager.getConnection(url , username , password ) ;
        // 刚获得的连接都是没关闭的
        assert !connection.isClosed();
        // 关闭连接
        connection.close();
        // 直接获得的是自动提交
        assert connection.getAutoCommit();
        // 关闭后就一直关闭了
        assert connection.isClosed();
    }
}
