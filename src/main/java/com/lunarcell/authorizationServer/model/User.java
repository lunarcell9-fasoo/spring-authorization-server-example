package com.lunarcell.authorizationServer.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class User extends ModelBase {
	
	private String userId;
	private String userName;
	@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
	private String userPwd;
	private String userEmail;
	private Boolean isUserPwdExpired;
	private Boolean isUserExpired;

	public String getUserId() {
		return this.userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getUserName() {
		return this.userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getUserPwd() {
		return this.userPwd;
	}

	public void setUserPwd(String userPwd) {
		this.userPwd = userPwd;
	}

	public String getUserEmail() {
		return this.userEmail;
	}

	public void setUserEmail(String userEmail) {
		this.userEmail = userEmail;
	}

	public Boolean getIsUserPwdExpired() {
		return this.isUserPwdExpired;
	}

	public void setIsUserPwdExpired(Boolean isUserPwdExpired) {
		this.isUserPwdExpired = isUserPwdExpired;
	}

	public Boolean getIsUserExpired() {
		return this.isUserExpired;
	}

	public void setIsUserExpired(Boolean isUserExpired) {
		this.isUserExpired = isUserExpired;
	}

}
