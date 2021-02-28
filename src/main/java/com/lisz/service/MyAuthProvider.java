package com.lisz.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class MyAuthProvider implements AuthenticationProvider {
	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// 这里可以限制重试次说，这里是做权限校验的地方
		System.out.println("校验用户名和密码是否匹配");

		String username = authentication.getPrincipal().toString(); // principle就是username
		String password = authentication.getCredentials().toString(); // credential就是password
		System.out.println("Authentication: " + authentication);
		System.out.println("Username: " + username);
		System.out.println("Password: " + password);

		UserDetails userDetails = myUserDetailsService.loadUserByUsername(username);
		if (passwordEncoder.matches(password, userDetails.getPassword())){ // 要用matches而不能用 == 或者 equals
			return new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());
		}

		throw new BadCredentialsException("用户名或密码错误，请重新输入");
	}

	// 标记是不是支持自定义配置
	@Override
	public boolean supports(Class<?> authentication) {
		return true;
	}
}
