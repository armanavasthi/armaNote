package com.arman.armaNote.model;

import java.io.Serializable;
import java.util.Date;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
//import javax.persistence.Transient;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Transient;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Entity
@Table(name="user")
@EntityListeners(EnableJpaAuditing.class)
@JsonIgnoreProperties(value={"createdAt", "lastLogin"})
public class User implements Serializable{
	
	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	@Column(name = "user_id")
	private Long id;
	
	@Column(nullable=false, unique=true, updatable=false)
	private String username;
	
	@Transient // see the note below
	private String password;
	
	@Column(unique=true)
	private String email;
	
	private String firstName;
	
	private String middleName;
	
	private String lastName;
	
	@Column(name = "active")
	private int active;
	
	public int getActive() {
		return active;
	}

	public void setActive(int active) {
		this.active = active;
	}

	@ManyToMany(cascade = CascadeType.ALL)
	@JoinTable(name="user_role",
				joinColumns = @JoinColumn(name="user_id"),
				inverseJoinColumns = @JoinColumn(name = "role_id")) // doubt : what if i want to keep my user and role table's id column as 'id' only, and not 'user_id', 'role_id'
	private Set<Role> roles;
	
	@Column(name="created_on", nullable=false, updatable=false)
	@Temporal(TemporalType.TIMESTAMP)
	@CreatedDate
	private Date createdAt = new Date();
	
	@Column(name="updated_on", nullable=false)
	@Temporal(TemporalType.TIMESTAMP)
	@LastModifiedDate // change it later, implement logic to updated it on user's last login
	//https://stackoverflow.com/questions/27956134/spring-security-update-last-login-date-on-authentication-success
	private Date lastLogin = new Date();

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getMiddleName() {
		return middleName;
	}

	public void setMiddleName(String middleName) {
		this.middleName = middleName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public Set<Role> getRoles() {
		return roles;
	}

	public void setRoles(Set<Role> roles) {
		this.roles = roles;
	}

	public Date getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(Date createdAt) {
		this.createdAt = createdAt;
	}

	public Date getLastLogin() {
		return lastLogin;
	}

	public void setLastLogin(Date lastLogin) {
		this.lastLogin = lastLogin;
	}
}

/*
 * Note: transient annotation used on password is from spring, not the one from hibernate
 * differences between then can be seen here
 * https://stackoverflow.com/questions/2154622/why-does-jpa-have-a-transient-annotation
 * https://stackoverflow.com/questions/42750977/transient-annotation-org-springframework-data-annotation-transient-annotation
 */
