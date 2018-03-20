package com.arman.armaNote.model;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.UniqueConstraint;
import javax.validation.constraints.NotBlank;

import org.hibernate.annotations.Cascade;
import org.hibernate.annotations.CascadeType;
import org.hibernate.annotations.Type;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Entity
@Table(name="note", uniqueConstraints = @UniqueConstraint(columnNames = { "title", "user_id" }))
@EntityListeners(EnableJpaAuditing.class)
@JsonIgnoreProperties(value={"createdAt", "updatedAt"})
public class Note implements Serializable {
	
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}

	public Date getCreatedOn() {
		return createdOn;
	}

	public void setCreatedOn(Date createdOn) {
		this.createdOn = createdOn;
	}

	public Date getUpdatedAt() {
		return updatedAt;
	}

	public void setUpdatedAt(Date updatedAt) {
		this.updatedAt = updatedAt;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	private Long id;
	
	private String title;
	
	@NotBlank
	//@Type(type="text") // this annotation and the below one work same, but this one is from hibernate and below is from spring data jpa
	@Column(name="content", columnDefinition = "TEXT")
	private String content;
	
	@Column(name="created_on", nullable=false, updatable=false)
	@Temporal(TemporalType.TIMESTAMP)
	@CreatedDate
	private Date createdOn;
	
	@Column(name="updated_on", nullable=false)
	@Temporal(TemporalType.TIMESTAMP)
	@LastModifiedDate
	private Date updatedAt;
	
	@ManyToOne(optional=false)
	@JoinColumn(name="user_id", nullable=false, foreignKey = @ForeignKey(name = "FK_NOTE_USER"))
	@Cascade({CascadeType.ALL})
	private User user;
}
