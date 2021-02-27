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
//		http.csrf()
//				.csrfTokenRepository(new HttpSessionCsrfTokenRepository()); //不忘往Cookie里写，往Session里面写
		http.authorizeRequests().anyRequest().authenticated()
			.and()
		    .formLogin().loginPage("/login.html")
				.loginProcessingUrl("/login")
				.permitAll()
				.failureForwardUrl("/login.html?error")
				.defaultSuccessUrl("/ok", true)
				.failureHandler(new AuthenticationFailureHandler() {
					@Override
					public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
						exception.printStackTrace();
						request.getRequestDispatcher(request.getRequestURL().toString()).forward(request, response);
					}
				})
			.and()
			.csrf()
			.csrfTokenRepository(new HttpSessionCsrfTokenRepository());

	}
}
