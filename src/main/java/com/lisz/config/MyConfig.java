package com.lisz.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class MyConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// 哪些 地址需要登录
		http.authorizeRequests()
			.anyRequest().authenticated() //所有请求都需要验证
			.and()
		        .formLogin().loginPage("/login.html")//自定义登录页
				.loginProcessingUrl("/login")
				.permitAll()
				.failureForwardUrl("/login.html?error")  // 登录失败 页面
				.defaultSuccessUrl("/login_success", true)  // 登录成功跳转的页面
				.usernameParameter("xx")
				.passwordParameter("oo")
				.failureHandler(new AuthenticationFailureHandler() {
					@Override
					public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
						exception.printStackTrace();
						//登录的时候账号或密码出错，则会抛出BadCredentialsException，可以用instanceof判断各种情况作出处理
						request.getRequestDispatcher(request.getRequestURL().toString()).forward(request, response);
						// 记录登录失败次数 禁止登录
					}
				})
			.and() //默认 所有的post请求 都会拦截, 看看有没有带token
			.csrf()
			.csrfTokenRepository(new HttpSessionCsrfTokenRepository()); //不往Cookie里写，往Session里面写

	}
}
