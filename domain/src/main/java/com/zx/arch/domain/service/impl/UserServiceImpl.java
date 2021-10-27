package com.zx.arch.domain.service.impl;


import com.zx.arch.domain.dao.UserDao;
import com.zx.arch.domain.entity.User;
import com.zx.arch.domain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


/**
 * @author Lenovo
 */
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

    @Override
    public void updateById(User user) {
        userDao.updateUserById(user);
    }

}