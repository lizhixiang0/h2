package com.mybatis.lizx;

import com.mybatis.lizx.dao.PersonDao;
import com.mybatis.lizx.model.Person;
import org.apache.ibatis.io.Resources;
import org.apache.ibatis.session.*;
import org.junit.Test;

import java.io.IOException;
import java.io.Reader;
import java.time.Period;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

public class TestFactory {
    /*mybatis技术内幕*/
    /*mybatis官方技术文档"https://mybatis.org/mybatis-3/zh/index.html*/
    /*mybatis中的设计模式：https://mp.weixin.qq.com/s/S9R_sZ246iaTyNLG-So9GQ*/
    // 缓存:"https://www.cnblogs.com/51life/p/9529409.html
    // 缓存:https://blog.csdn.net/finalcola/article/details/81155517
    // spring使用缓存“https://www.cnblogs.com/ssskkk/p/11097159.html
    /*https://blog.csdn.net/qq_35571554/article/details/82629253*/
    /*https://juejin.cn/post/6844903841163378701
    /*https://www.iteye.com/blog/elim-2353672*/
    /*https://blog.csdn.net/iteye_11305/article/details/82678034?utm_medium=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-2.control&depth_1-utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-2.control*/
    /*https://my.oschina.net/zudajun/blog/665956*/
    /*https://www.cnblogs.com/zhjh256/p/8512392.html*/
    /*超全配置文件“https://www.jianshu.com/p/232928bf5010*/
    /*mybatis事务认识"https://www.cnblogs.com/timfruit/p/11508873.html*/
    /*spring-mybatis : http://mybatis.org/spring/zh/getting-started.html*/


    /*这个人博客写的不错！https://blog.csdn.net/lqzkcx3/article/details/78370497*/
    @Test
    public void test() throws IOException {

        String path = "mybatis-config.xml";
        String path1 = "dbconfig.properties";
        // 1、通过自定义的资源加载类加载配置文件
        Reader reader = Resources.getResourceAsReader(path);
        Properties properties = Resources.getResourceAsProperties(path1);
        // 2、通过构造器解析配置文件生成会话工厂

        SqlSessionFactory sqlSessionFactory = new SqlSessionFactoryBuilder().build(reader,properties);
        SqlSessionManager sqlSessionManager = SqlSessionManager.newInstance(sqlSessionFactory);
        // 3、SqlSession是数据库的C、R、U、D及事务处理接口
        SqlSession sqlSession = sqlSessionManager.openSession();
        PersonDao personDao =  sqlSession.getMapper(PersonDao.class);

//        Person pp = sqlSession.selectOne("getById",13L);
        /**
         * 第一次查询
         */
//        Person person = personDao.getById(1L);
//        System.out.println(person);

//        /**
//         * 第二次查询
//         */
//        HashMap person1 = personDao.getPerson(43L);



//        System.out.println(person1);


       /* // 使用RowBounds实现分页
        int currentPage = 1; //当前页
        int pageSize = 10; //页面大小

        RowBounds rowBounds = new RowBounds((currentPage - 1) * pageSize, pageSize);

        //注意点；使用RowBounds就不能使用getMapper了
        //selectList: 接收一个List
        //selectMap: 接收一个Map
        //selectOne ： 接收只有一个对象的时候

        List<Person> persons = sqlSession.selectList("com.mybatis.lizx.dao.PersonDao.selectPersonByRowBounds", null, rowBounds);


        for (Person user : persons) {
            System.out.println(user);
        }*//* // 使用RowBounds实现分页
        int currentPage = 1; //当前页
        int pageSize = 10; //页面大小

        RowBounds rowBounds = new RowBounds((currentPage - 1) * pageSize, pageSize);

        //注意点；使用RowBounds就不能使用getMapper了
        //selectList: 接收一个List
        //selectMap: 接收一个Map
        //selectOne ： 接收只有一个对象的时候

        List<Person> persons = sqlSession.selectList("com.mybatis.lizx.dao.PersonDao.selectPersonByRowBounds", null, rowBounds);


        for (Person user : persons) {
            System.out.println(user);
        }*/

        Person p = new Person("chen",12,"111","157538651@qq.com",new Date(),"上海");
        personDao.insert(p);
        System.out.println(p.toString());

        /**
         * 事务提交
         */
        sqlSession.commit();
        sqlSession.close();
        //sqlSession.commit();


    }

}
