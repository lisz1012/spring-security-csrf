package com.lisz.service;

import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Random;

@Service
public class MyUserDetailsService implements UserDetailsService {
	// 按说应该在这里查询数据库
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		if (new Random().nextBoolean()) {
			// 登录成功
			throw new CredentialsExpiredException("密码过期，请先修改密码");
		} else {
			throw new LockedException("用户已经被锁定，请联系管理员");
		}
		//return null;
	}
}
