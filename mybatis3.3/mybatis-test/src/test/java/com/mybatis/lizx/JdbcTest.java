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
 * @description ���Լ򵥵�jdbc����
 **/
public class JdbcTest {
    @Test
    public void test() throws SQLException, ClassNotFoundException {
        Class.forName("com.mysql.cj.jdbc.Driver") ;
        String url = "jdbc:mysql://localhost:3306/db_mybatis?serverTimezone=GMT%2B8" ;
        String username = "root" ;
        String password = "root" ;
        Connection connection = DriverManager.getConnection(url , username , password ) ;
        // �ջ�õ����Ӷ���û�رյ�
        assert !connection.isClosed();
        // �ر�����
        connection.close();
        // ֱ�ӻ�õ����Զ��ύ
        assert connection.getAutoCommit();
        // �رպ��һֱ�ر���
        assert connection.isClosed();
    }
}
