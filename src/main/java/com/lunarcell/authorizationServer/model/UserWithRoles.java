package com.lunarcell.authorizationServer.model;

import java.util.List;

public class UserWithRoles extends User {
	
	private List<String> roleNames;

	public List<String> getRoleNames() {
		return this.roleNames;
	}

	public void setRoleNames(List<String> roleNames) {
		this.roleNames = roleNames;
	}

}
