package com.lisz.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HiController {
	@GetMapping("/hi")
	@Secured({"ROLE_user", "ROLE_admin"}) // 获的关系。继承好像不管用：只写ROLE_user，但是ROLE_user能访问的网页ROLE_admin不行。不支持"并且"，user有ROLE_user和ROLE_admin两个角色也是无权访问的，这个时候要用@PreAuthorizes这个注解
	public String hello(){
		return "hi";
	}

	@GetMapping("/admin/hi")
	public String helloAdmin(){
		return "hi admin";
	}

	@GetMapping("/user/hi")
	public String helloUser(){
		return "hi user";
	}
}
