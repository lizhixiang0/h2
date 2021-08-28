package com.mybatis.lizx;

import org.junit.Test;

import java.io.IOException;
import java.sql.*;

/**
 * @author lizx
 * @since 1.0.0
 * @description 测试简单的jdbc代码
 * @blog "https://www.jianshu.com/p/e8571cba96d3
 **/
public class JdbcTest {
    protected String poolPingQuery = "SELECT *  FROM paxvas_appscan.ac_task where env_code = 'sit' and status = 'F' order by created_time desc limit 0,1;";

    @Test
    public void test() throws SQLException, ClassNotFoundException {
        Class.forName("com.mysql.cj.jdbc.Driver") ;
        String url = "jdbc:mysql://localhost:3306/paxvas_appscan?serverTimezone=CST" ;
        String username = "root" ;
        String password = "root" ;
        DriverManager.setLoginTimeout(10);
        Connection connection = DriverManager.getConnection(url , username , password ) ;


        System.out.println(connection.getMetaData().getDatabaseProductName());
        // b、创建Statement （sql）
        Statement statement = connection.createStatement();
        // c、传递参数
        ResultSet rs = statement.executeQuery(poolPingQuery);

        ResultSetMetaData meta = rs.getMetaData();

        Timestamp date = null;
        while (rs.next()) {
            int colcount = meta.getColumnCount();
            for (int i=1;i<=colcount;i++){
                String created_time = meta.getColumnLabel(i);
                if (created_time.equals("created_time"))
                date = rs.getTimestamp(i);
            }
        }

        System.out.println(date);


        // d、关闭rs和statement
        rs.close();
        statement.close();

       /* // 刚获得的连接都是没关闭的
        assert !connection.isClosed();
        // 关闭连接
        connection.close();
        // 直接获得的是自动提交
        assert connection.getAutoCommit();
        // 关闭后就一直关闭了
        assert connection.isClosed();*/
    }
}
