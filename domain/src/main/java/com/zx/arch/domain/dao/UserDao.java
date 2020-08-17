package com.zx.arch.domain.dao;

import com.zx.arch.domain.entity.User;
import org.springframework.stereotype.Repository;

/**
 * @author lizx
 * @date 2020/08/13
 **/
@Repository
public interface UserDao{
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
