package com.mybatis.lizx;

import com.mybatis.lizx.dao.PersonDao;
import com.mybatis.lizx.model.Person;
import com.mybatis.lizx.util.SqlSessionFactoryUtil;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.junit.Test;

public class TestFactory {
    @Test
    public void test(){
        SqlSessionFactory sqlSessionFactory = SqlSessionFactoryUtil.getSqlSessionFactory();
        SqlSession sqlSession = sqlSessionFactory.openSession();
        PersonDao personDao =  sqlSession.getMapper(PersonDao.class);
        Person p = new Person();
        p.setAddress("广东省");
        p.setAge(12);
        p.setEmail("157538651@qq.com");
        p.setName("chen");
        p.setPhone("15345634565");
        personDao.insert(p);
        System.out.println(p.toString());
        sqlSession.commit();
        sqlSession.close();
    }
}
