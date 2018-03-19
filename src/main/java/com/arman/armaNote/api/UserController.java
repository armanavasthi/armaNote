package com.arman.armaNote.api;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
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
	
	@RequestMapping(path = "/", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
	public List<User> getUsers(){
		return userService.getAllUsers();
	}
	
	
}
