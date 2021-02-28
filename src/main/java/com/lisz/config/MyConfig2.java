package com.lisz.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import java.util.Base64;

@Configuration
@EnableWebSecurity
public class MyConfig2 extends WebSecurityConfigurerAdapter { // 这个类里面，有很多的注视，说明了该怎么写代码做各种校验功能
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.anyRequest() //所有请求都需要验证
			.authenticated()
			.and()
				.formLogin() // 提供登录表单
			// 异地登录就把以前的踢下线, 前面的Session会失效 (跟下面的rememberMe冲突，必须注掉其中一个)
			.and()
				.sessionManagement()
					.maximumSessions(1)// 允许同时登录的客户端
					.maxSessionsPreventsLogin(true) // 已经有max个用户登录则不允许这个账号异地登录，没有这一句会把前面的踢掉
				// cookies 来访的不一定是浏览器，集群的会话，session共享压力非常大，因为session里面还可以存各种键值对，整个session 对象的共享。
				// rememberMe是对于token的，没有会话。用了rememberMe会在前端有一个Remember Me的checkbox，勾上之后发请求，
				// 会在Cookies中有一个remember-me键值对，其中值是：MTIzOjE2MTQ1MDMxODM3NTM6ZjAwYWYzZTJkYjY4MjEwMTUxZDExNjdmMzA2NjE3MDg
				// 是个Base64，可逆的，用下面的main方法解码，可得：123:1614503183753:f00af3e2db68210151d1167f30661708
				// 第一项是用户名，第二项是过期时间，都不存在服务器里，最后一项sign，存在服务器，里用来校验前两项
				// 用户名+ 权限 + 欢乐豆 + 过期时间 + secret  = 摘要 首次登录（服务器端有 客户端没有） secret要参与，这样才可以防止客户端篡改用户名和过期时间之后登录
				// secret只保存在服务端。在这里是那用户的密码商城的最后这项摘要。这个方法不用在服务器端走数据库
//			.and()
//				.rememberMe()
//				.tokenValiditySeconds(60) // 记多长时间(秒)
			.and().and()
				.csrf().disable();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// session 登录  并发量高 -> jwt (无状态的)。当往Redis里面写的时候已经不能用这个了，必须得用jwt
		auth.inMemoryAuthentication()
				.withUser("123")
				.password(passwordEncoder.encode("123"))
				.roles("admin")
			.and()
				.withUser("321")
				.password(passwordEncoder.encode("321"))
				.roles("user");
	}

	public static void main(String[] args) {
		byte[] decode = Base64.getDecoder().decode("MTIzOjE2MTQ1MDMxODM3NTM6ZjAwYWYzZTJkYjY4MjEwMTUxZDExNjdmMzA2NjE3MDg");
		System.out.println(new String(decode));
	}

	// 及时清理过期的Session，好像有时也用不着
//	@Bean
//	public HttpSessionEventPublisher httpSessionEventPublisher(){
//		return new HttpSessionEventPublisher();
//	}
}
