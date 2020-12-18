package com.mybatis.lizx;

import com.mybatis.lizx.dao.PersonDao;
import com.mybatis.lizx.model.Person;
import com.mybatis.lizx.util.SqlSessionFactoryUtil;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.junit.Test;

public class TestFactory {
    /*https://blog.csdn.net/qq_28807077/article/details/111322573*/
    /*https://www.iteye.com/blog/elim-2353672*/
    /*https://blog.csdn.net/iteye_11305/article/details/82678034?utm_medium=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-2.control&depth_1-utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-2.control*/

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
