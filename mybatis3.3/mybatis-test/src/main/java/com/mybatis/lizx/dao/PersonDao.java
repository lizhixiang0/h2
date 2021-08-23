package com.mybatis.lizx.dao;

import com.mybatis.lizx.model.Person;
import org.apache.ibatis.annotations.Select;

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

    @Select("select p.name,p.age,p.phone,p.email,p.create_time as createTime, p.address from person p where p.id = #{id}")
    Person getById(Long id);

    HashMap<String, Object> getPerson(Long i);

    /**
     * 查询全部用户（使用RowBounds实现分页）
     * @return
     */
    List<Person> selectPersonByRowBounds();
}
