package com.lunarcell.authorizationServer.model;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

public class Account extends UserWithRoles implements UserDetails {

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		List<String> roleNames = getRoleNames();
		String[] rolesArray = roleNames.toArray(new String[roleNames.size()]);
		for (int i = 0; i < rolesArray.length; i++) {
			rolesArray[i] = "ROLE_" + rolesArray[i];
		}

		return AuthorityUtils.createAuthorityList(rolesArray);
	}

	@Override
	public String getPassword() {
		return this.getUserPwd();
	}

	@Override
	public String getUsername() {
		return this.getUserId();
	}

	@Override
	public boolean isAccountNonExpired() {
		return !this.getIsUserExpired();
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
	
}
