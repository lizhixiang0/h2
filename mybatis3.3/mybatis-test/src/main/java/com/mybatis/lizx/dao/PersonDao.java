package com.mybatis.lizx.dao;

import com.mybatis.lizx.model.Person;

import java.time.Period;

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
}
