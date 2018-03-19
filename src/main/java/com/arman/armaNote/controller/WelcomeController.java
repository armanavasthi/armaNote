package com.arman.armaNote.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import com.arman.armaNote.model.User;
import com.arman.armaNote.service.UserService;

@Controller
public class WelcomeController {
	
	@Autowired
	private UserService userService;
	
	@RequestMapping(value="/", method=RequestMethod.GET)
	public String showWelcomePage() {
		return "main";
	}
	
	@RequestMapping(value="/admin/home", method=RequestMethod.GET)
	public String showAdminHomePage() {
		return "adminhome";
	}
	
	@RequestMapping(value="/user/home", method=RequestMethod.GET)
	public String showUserHomePage() {
		return "userHome";
	}
	
	@RequestMapping(value="/login", method=RequestMethod.GET)
	public ModelAndView showLoginPage() {
		return new ModelAndView("login");
	}
	
	@RequestMapping(value="/registration", method=RequestMethod.GET)
	public ModelAndView showRegistrationPage() {
		ModelAndView mav = new ModelAndView();
		mav.addObject(new User());
		mav.setViewName("registration");
		return mav;
	}
	
	@RequestMapping(value="/registration", method=RequestMethod.POST)
	public ModelAndView saveRegistrationInfo(@Valid User user, BindingResult bindingResult) { // @RequestBody doesn't work here.
		ModelAndView mav = new ModelAndView();
		User userExists = userService.findUserByEmail(user.getEmail());
		if (userExists != null) {
			bindingResult.rejectValue("email", "error.user", "There is already a registered user with this email");
		}
		
		if (bindingResult.hasErrors()) {
			mav.setViewName("registration");
		}
		else {
			userService.saveUser(user);
			mav.addObject("successMessage", "User has been registered successfully!!!");
			mav.addObject(new User());
			mav.setViewName("registration");
		}
		
		return mav;
	}
}
