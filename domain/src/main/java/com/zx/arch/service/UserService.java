/**
 * 
 */
package com.zx.arch.service;


import com.zx.arch.entity.User;

public interface UserService {
		int insert(User user);
	    User getUserById(Long id);
}