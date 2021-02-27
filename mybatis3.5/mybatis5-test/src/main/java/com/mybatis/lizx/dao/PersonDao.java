package com.mybatis.lizx.dao;

import com.mybatis.lizx.model.Person;

import java.time.Period;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    HashMap<String, Object> getPerson(Long i);

    /**
     * 查询全部用户（使用RowBounds实现分页）
     * @return
     */
    List<Person> selectPersonByRowBounds();
}
