package com.lunarcell.authorizationServer.model;

import java.util.Date;

public abstract class ModelBase {
	private Date createdAt;
	private Date updatedAt;

	public Date getCreatedAt() {
		return createdAt;
	}
	public void setCreatedAt(Date createdAt) {
		this.createdAt = createdAt;
	}
	public Date getUpdatedAt() {
		return updatedAt;
	}
	public void setUpdatedAt(Date updatedAt) {
		this.updatedAt = updatedAt;
	}
}
