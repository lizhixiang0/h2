/**
 * 
 */
package com.zx.arch.domain.service;


import com.zx.arch.domain.entity.User;

public interface UserService {
		int insert(User user);
	    User getUserById(Long id);
}