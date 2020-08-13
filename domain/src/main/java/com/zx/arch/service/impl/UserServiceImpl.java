/**
 * 
 */
package com.zx.arch.service.impl;


import com.zx.arch.dao.UserDao;
import com.zx.arch.entity.User;
import com.zx.arch.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserDao userDao;

    @Override
    public int insert(User user) {
        return userDao.insert(user);
    }

    @Override
    public User getUserById(Long id) {
        return userDao.getUserById(id);
    }
}