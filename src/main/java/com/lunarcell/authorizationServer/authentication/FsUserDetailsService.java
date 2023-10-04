package com.lunarcell.authorizationServer.authentication;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.lunarcell.authorizationServer.model.UserWithRoles;
import com.lunarcell.authorizationServer.service.UserService;

// AuthenticationManagerBuilder 사용시
//@Component
public class FsUserDetailsService implements UserDetailsService {

	@Autowired
	private UserService userService;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	
		UserWithRoles user = userService.getUserWithRoles(username);

		if (user == null) {
			throw new UsernameNotFoundException(username);
		}

		List<String> roleNames = user.getRoleNames();
		String[] rolesArray = roleNames.toArray(new String[roleNames.size()]);
		for (int i = 0; i < rolesArray.length; i++) {
			rolesArray[i] = "ROLE_" + rolesArray[i];
		}

		return new User(user.getUserId(), user.getUserPwd(), true, !user.getIsUserExpired(), !user.getIsUserPwdExpired(), true, AuthorityUtils.createAuthorityList(rolesArray));
	}
	
}
