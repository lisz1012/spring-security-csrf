package com.lisz.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Random;

/*
以下的配置是为了开发测试方便的，针对于inMemory的User，如果要给予JDBC，则需要剪标、加Filter写代码，回到了之前的RBAC
建立角色表和权限表，并且建立好关系
 */
@RestController
public class HiController {
	@GetMapping("/hi")
	@Secured({"ROLE_user", "ROLE_admin"}) // 获的关系。继承好像不管用：只写ROLE_user，但是ROLE_user能访问的网页ROLE_admin不行。不支持"并且"，user有ROLE_user和ROLE_admin两个角色也是无权访问的，这个时候要用@PreAuthorizes这个注解。
	//@EnableGlobalMethodSecurity(securedEnabled = true) 才能使得 @Secured 注解生效
	public String hello(){
		return "hi";
	}

	@GetMapping("/admin/hi")
	@PreAuthorize("hasRole('ROLE_admin')") // @EnableGlobalMethodSecurity(prePostEnabled = true) @PreAuthorize 才能生效
	public String helloAdmin(){
		return "hi admin";
	}

	@GetMapping("/user/hi")
	public String helloUser(){
		return "hi user";
	}

	@GetMapping("/adminOrGuest/hi")
	@PreAuthorize("hasAnyRole('ROLE_admin', 'ROLE_guest')") // 等同于上面的@Secured({"ROLE_user", "ROLE_admin"})，任意一个都可以
	public String helloAdminOrGuest(){
		return "hi Admin or Guest";
	}

	@GetMapping("/adminAndGuest/hi")
	@PreAuthorize("hasRole('ROLE_admin') and hasRole('ROLE_guest')") // 必须要同时有admin和guest角色
	public String helloAdminAndGuest(){
		return "hi Admin and Guest";
	}

	@GetMapping("/admin/hi5")
	// Spring EL表达式. 根据返回值判断有没有权限
	@PostAuthorize("returnObject == 1") // 必须要同时有admin和guest角色
	public int helloAdminPostAuthorize(){
		// 一般会访问其他的子系统，把当前的角色信息带过去，那个子系统（远程服务）就会去识别信息，并决定能不能访问。能访问就执行正常的业务逻辑；
		// 如果不能访问，则在这里也会根据返回值报错。也就是说权限并不在这一层服务判断
		return new Random().nextInt(2);
	}
}
