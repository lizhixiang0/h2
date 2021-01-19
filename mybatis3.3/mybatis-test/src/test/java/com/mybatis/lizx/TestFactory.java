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
import java.util.Properties;

public class TestFactory {
    /*mybatis技术内幕*/
    /*mybatis中的设计模式：https://mp.weixin.qq.com/s/S9R_sZ246iaTyNLG-So9GQ*/
    // 缓存:"https://www.cnblogs.com/51life/p/9529409.html
    // 缓存:https://blog.csdn.net/finalcola/article/details/81155517
    /*https://blog.csdn.net/qq_35571554/article/details/82629253*/
    /*https://juejin.cn/post/6844903841163378701
    /*https://www.iteye.com/blog/elim-2353672*/
    /*https://blog.csdn.net/iteye_11305/article/details/82678034?utm_medium=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-2.control&depth_1-utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-2.control*/
    /*https://my.oschina.net/zudajun/blog/665956*/
    /*https://www.cnblogs.com/zhjh256/p/8512392.html*/
    @Test
    public void test() throws IOException {

        String path = "mybatis-config.xml";
        String path1 = "dbconfig.properties";
        // 1、通过自定义的资源加载类加载配置文件
        Reader reader = Resources.getResourceAsReader(path);
        Properties properties = Resources.getResourceAsProperties(path1);
        // 2、通过构造器解析配置文件生成会话工厂
        SqlSessionFactory sqlSessionFactory = new SqlSessionFactoryBuilder().build(reader,properties);
        // 3、SqlSession是数据库的C、R、U、D及事务处理接口
        SqlSession sqlSession = sqlSessionFactory.openSession();
        PersonDao personDao =  sqlSession.getMapper(PersonDao.class);

        Person p = new Person("chen",12,"ss","157538651@qq.com","广东省");
        personDao.insert(p);
        System.out.println(p.toString());
        /**
         * 第一次查询
         */
        Person person = personDao.getById(13L);
        /**
         * 事务提交
         */
        sqlSession.commit();
        /**
         * 第二次查询
         */
        Person person1 = personDao.getById(0L);
        sqlSession.close();

        System.out.println(person);
        System.out.println(person1);


    }
}
