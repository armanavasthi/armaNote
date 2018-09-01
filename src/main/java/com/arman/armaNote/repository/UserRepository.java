package com.arman.armaNote.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.arman.armaNote.model.User;

@Repository("userRepository")
public interface UserRepository extends JpaRepository<User, Long> {
	User findByEmail(String email);
	
	// https://www.baeldung.com/spring-data-jpa-query
	@Query(value="select r.role from user u inner join user_role ur on(u.user_id=ur.user_id) inner join role r on(ur.role_id=r.role_id) where u.email=?1",
			nativeQuery=true)
	public String findUserRole(String email);
	
	@Query(value="select * from user where email=?1 or username=?1",
			nativeQuery=true)
	User findByUsernameOrEmail(String email);
}
