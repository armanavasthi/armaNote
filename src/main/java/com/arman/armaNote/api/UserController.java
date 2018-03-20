package com.arman.armaNote.api;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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
	public ResponseEntity<Map> getUsers(){
		Map response = new HashMap();
		List<User> users = userService.getAllUsers();
		HttpHeaders httpHeader = new HttpHeaders();
		httpHeader.add("success", "true");
		
		response.put("success", true);
		response.put("Data", users);
		
		return new ResponseEntity<Map>(response, httpHeader ,HttpStatus.OK);
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
	@PutMapping(value="/", consumes=MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Boolean> updateUser(@RequestBody User user1) {
		User user = null;
		String currentUsername = userService.getCurrentUsername();
		HttpHeaders httpHeaders = new HttpHeaders();
		HttpStatus httpStatus = null;
		
		if(user1 == null || user1.getEmail() == null) {
			httpHeaders.add("message", "Please send proper user details");
			httpStatus = HttpStatus.NOT_FOUND;
		}
		else {
			user = userService.findUserByEmail(user1.getEmail());
		}

		if(user == null) {
			httpHeaders.add("message", "There is no user with this email");
			httpStatus = HttpStatus.NOT_FOUND;
		}
		else if (!user1.getEmail().equalsIgnoreCase(currentUsername)) {
			httpHeaders.add("message", "You are not authorized to change other user's informations");
			httpStatus = HttpStatus.UNAUTHORIZED;
		}
		else if (!user1.getUsername().equals(user.getUsername())) {
			httpHeaders.add("message", "You cannot change your username");
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
