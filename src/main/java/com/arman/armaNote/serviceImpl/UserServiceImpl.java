package com.arman.armaNote.serviceImpl;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.arman.armaNote.model.Role;
import com.arman.armaNote.model.User;
import com.arman.armaNote.repository.RoleRepository;
import com.arman.armaNote.repository.UserRepository;
import com.arman.armaNote.service.UserService;

@Service("userService")
public class UserServiceImpl implements UserService {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private RoleRepository roleRepository;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	public User findUserByEmail(String email) {
		return userRepository.findByEmail(email);
	}
	
	public void saveUser(User user) {
		// encrypting the password
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		
		// conditions for different roles for now the user is always of "USER" type (no admin, no visitor for now)
		Role role = roleRepository.findByRole("USER");
		user.setRoles(new HashSet<Role>(Arrays.asList(role)));
		
		
		userRepository.save(user);
	}
	
	public List<User> getAllUsers(){
		return userRepository.findAll();
	}
	
	// below code is taken from http://www.baeldung.com/get-user-in-spring-security
	// there are other nice ways to get current user given in the link above. Please do read.
	@Override
	public String getCurrentUsername() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String currentUserName = null;
		if (!(authentication instanceof AnonymousAuthenticationToken)) {
		    currentUserName = authentication.getName();
		    System.out.println(currentUserName);
		}
		return currentUserName;  // note that currently it is returning email, bcz of our security setup.
	}
}
