package com.arman.armaNote.api;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.arman.armaNote.model.User;
import com.arman.armaNote.service.UserService;

@RestController
@RequestMapping("/webservice/user")
public class UserController {
	
	@Autowired
	private UserService userService;
	
	@GetMapping(path = "/", produces = MediaType.APPLICATION_JSON_VALUE)
	public List<User> getUsers(){
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (!(authentication instanceof AnonymousAuthenticationToken)) {
		    String currentUserName = authentication.getName();
		    System.out.println(currentUserName);
		}
		return userService.getAllUsers();
	}
	
	@GetMapping(value="/{email}", produces=MediaType.APPLICATION_JSON_VALUE)
	public User getUser(@PathVariable String email) {
		return userService.findUserByEmail(email);
	}
	
	/*
	 *  Changes to be done in api below:
	 *  Remove path variable email as we can get it from requestbody.
	 *  Make sure that even if username is passed through requestBody, it should not be updated
	*/
	@PutMapping(value="/{email}", consumes=MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Boolean> updateUser(@PathVariable String email, 
												@RequestBody User user1) {
		
		User user = userService.findUserByEmail(email);
		String currentUsername = userService.getCurrentUsername();
		HttpHeaders httpHeaders = new HttpHeaders();
		HttpStatus httpStatus = null;
		if(user == null || user1 == null) {
			httpHeaders.add("message", "There is no user with this email or you haven't send a proper user");
			System.out.println("not found 22222222222222");
			httpStatus = HttpStatus.NOT_FOUND;
		}
		else if (!user1.getEmail().equalsIgnoreCase(currentUsername)) {
			httpHeaders.add("message", "You are not authorized to change other user's informations");
			System.out.println("not auth 1111111111111");
			httpStatus = HttpStatus.UNAUTHORIZED;
		}
		else {
			userService.saveUser(user1);
			httpHeaders.add("message", "User details are updated successfully");
			httpStatus = HttpStatus.OK;
		}
		return new ResponseEntity<Boolean>(true, httpHeaders, httpStatus);
	}
}
