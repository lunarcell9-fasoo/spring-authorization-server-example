package com.lunarcell.authorizationServer.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lunarcell.authorizationServer.mapper.UserMapper;
import com.lunarcell.authorizationServer.model.UserWithRoles;

@Service
public class UserService {
	
	@Autowired
	UserMapper userMapper;

	public UserWithRoles getUserWithRoles(String userId) {

		return userMapper.getWithRoles(userId);
	}
}
