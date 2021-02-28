package com.lisz.config;

import com.lisz.service.MyUserDetailsService;
import com.mysql.cj.jdbc.MysqlDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class MyConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private PasswordEncoder passwordEncoder;

	// Springboot自动读取配置文件之后注入
	@Autowired
	private DataSource dataSource;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		String pass1 = passwordEncoder.encode("123");
		String pass2 = passwordEncoder.encode("123");
		System.out.println(pass1);
		System.out.println(pass2);
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
						if (exception instanceof CredentialsExpiredException ||
							exception instanceof LockedException) {
							request.getSession().setAttribute("errorMessage", exception.getMessage());
						} else if (exception.getCause() instanceof CredentialsExpiredException ||
								exception.getCause() instanceof LockedException) {
							request.getSession().setAttribute("errorMessage", exception.getCause().getMessage());
						}
						request.getRequestDispatcher(request.getRequestURL().toString()).forward(request, response);
						// 记录登录失败次数 禁止登录
					}
				})
			.and() //默认 所有的post请求 都会拦截, 看看有没有带token
			.csrf()
			.csrfTokenRepository(new HttpSessionCsrfTokenRepository()); //不往Cookie里写，往Session里面写
	}

	// 账号密码存在内存里
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		// session 登录  并发量高 -> jwt (无状态的)。当往Redis里面写的时候已经不能用这个了，必须得用jwt
//		auth.inMemoryAuthentication()
//				.withUser("123")
//				.password(passwordEncoder.encode("123"))
//				.roles("admin")
//			.and()
//				.withUser("321")
//				.password(passwordEncoder.encode("321"))
//				.roles("user");
//	}

	// 测试这里的时候最好把上面的 protected void configure(AuthenticationManagerBuilder auth) throws Exception 注释掉， 谢谢
//	@Bean
//	public UserDetailsService userDetailsService(){
//		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//		User user = new User("a", passwordEncoder.encode("1"),
//				true, true, true, true,
//				Collections.singletonList(new SimpleGrantedAuthority("xx")));
//		manager.createUser(user);
//		manager.createUser(User
//					.withUsername("xiaoming")
//					.password(passwordEncoder.encode("xx")) // 下面有Encoder所以这里必须要加密
//					.roles("xxz") // 必须指定角色
//				.build());
//		return manager;
//	}

	// 把账号和密码放在数据库里，每次启动要删掉，因为每次都会尝试新建
	// 数据库要准备好，建表语句在：org.springframework.security.core.userdetails.jdbc的users.ddl里
//	@Bean
//	public UserDetailsService userDetailsService(){
//		JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);
//		manager.createUser(User
//				.withUsername("xiaoming2")
//				.password(passwordEncoder.encode("xx")) // 每次加密后的密码不一样，因为盐不一样，BCryptPasswordEncoder有哦你个Random生成盐
//				.roles("admin", "user")
//				.build());
//		return manager;
//	}


	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		JdbcUserDetailsManager manager = auth
//				.jdbcAuthentication()
//				.dataSource(dataSource).getUserDetailsService();
//		if (manager.userExists("xiaoming3")){
//			manager.deleteUser("xiaoming3");
//		}
//		manager.createUser(User
//				.withUsername("xiaoming3")
//				.password(passwordEncoder.encode("aaa"))
//				.roles("bbb") // 角色要指定
//				.build());
		auth.userDetailsService(new MyUserDetailsService());
	}

	// 有这个Bean之后用上面的123 和 321 就能登录成功了
	@Bean
	public PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
}
