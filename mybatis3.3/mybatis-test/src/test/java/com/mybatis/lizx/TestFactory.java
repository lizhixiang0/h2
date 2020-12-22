package com.mybatis.lizx;

import com.mybatis.lizx.dao.PersonDao;
import com.mybatis.lizx.model.Person;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.junit.Test;

import java.io.IOException;
import java.io.Reader;

public class TestFactory {
    /*https://blog.csdn.net/qq_28807077/article/details/111322573*/
    /*https://www.iteye.com/blog/elim-2353672*/
    /*https://blog.csdn.net/iteye_11305/article/details/82678034?utm_medium=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-2.control&depth_1-utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-2.control*/
    /*https://my.oschina.net/zudajun/blog/668323?p=1*/
    @Test
    public void test() throws IOException {

        String path = "mybatis-config.xml";
        Reader reader = Resources.getResourceAsReader(path);
        SqlSessionFactory sqlSessionFactory = new SqlSessionFactoryBuilder().build(reader);
        SqlSession sqlSession = sqlSessionFactory.openSession();
        PersonDao personDao =  sqlSession.getMapper(PersonDao.class);

        Person p = new Person("chen",12,"15345634565","157538651@qq.com","广东省");
        personDao.insert(p);

        System.out.println(p.toString());

        sqlSession.commit();
        sqlSession.close();
    }
}
