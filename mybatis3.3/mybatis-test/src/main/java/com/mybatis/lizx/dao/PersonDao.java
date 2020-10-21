package com.mybatis.lizx.dao;

import com.mybatis.lizx.model.Person;

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
}
