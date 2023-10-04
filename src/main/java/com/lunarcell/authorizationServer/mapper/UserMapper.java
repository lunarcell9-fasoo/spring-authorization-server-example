package com.lunarcell.authorizationServer.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.lunarcell.authorizationServer.model.UserWithRoles;

@Mapper
public interface UserMapper {
	
	UserWithRoles getWithRoles(@Param("userId") String userId);

}
