package com.zx.arch.dao;

import com.zx.arch.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

/**
 * @author lizx
 * @date 2020/08/13
 **/
@Mapper
@Repository
public interface UserDao {
    /**
     *
     * @param user
     * @return
     */
    int insert(User user);

    /**
     *
     * @param id
     * @return
     */
    User getUserById(Long id);
}
