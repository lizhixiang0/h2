package com.mybatis.lizx.dao;

import com.mybatis.lizx.model.Person;

import java.time.Period;
import java.util.List;

/**
 * @author lizx
 * @since 1.0.0
 **/
public interface PersonDao {
    /**
     *
     * @param p
     * @return
     */
    int insert(Person p);

    Person getById(Long id);

    //查询全部用户（使用RowBounds实现分页）
    List<Person> selectPersonByRowBounds();
}
