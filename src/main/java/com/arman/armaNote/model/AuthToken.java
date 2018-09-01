package com.arman.armaNote.model;

public class AuthToken {
	
	String token;
	
	public AuthToken(String token) {
		this.token = token;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
}
