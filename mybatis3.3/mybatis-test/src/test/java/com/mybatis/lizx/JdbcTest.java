package com.mybatis.lizx;

import org.junit.Test;

import java.io.IOException;
import java.sql.*;

/**
 * @author lizx
 * @since 1.0.0
 * @description ���Լ򵥵�jdbc����
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
        // b������Statement ��sql��
        Statement statement = connection.createStatement();
        // c�����ݲ���
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


        // d���ر�rs��statement
        rs.close();
        statement.close();

       /* // �ջ�õ����Ӷ���û�رյ�
        assert !connection.isClosed();
        // �ر�����
        connection.close();
        // ֱ�ӻ�õ����Զ��ύ
        assert connection.getAutoCommit();
        // �رպ��һֱ�ر���
        assert connection.isClosed();*/
    }
}
