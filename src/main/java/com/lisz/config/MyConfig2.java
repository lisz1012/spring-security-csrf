package com.lisz.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class MyConfig2 extends WebSecurityConfigurerAdapter { // 这个类里面，有很多的注视，说明了该怎么写代码做各种校验功能
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			// 下面两行设置某个IP无需登录。封IP可以在springboot上坐，用Filter，应该在Linux运维级别或者nginx这里拦住，请求打在Tomcat上，已经是重量级的了。新的react模型就是基于Netty和Servlet 3.1的
			// 拦截和缓存最好前置.https://blog.csdn.net/neweastsun/article/details/104727863 Filter比HandlerInterceptor优先执行，因为前者是JavaEE级别的，或者是SpringMVC级别的
			//.antMatchers("url").hasIpAddress("192.168.1.102")
//				.antMatchers("/**/*")
//				.access("hasIpAddress('192.168.1.102')") // 这里不能用 127.0.0.1, 否则还是会被要求登录
//			.anyRequest() //所有请求都需要验证
//			.authenticated()
			// 把角色和权限进行了匹配 角色 -> URL
			.antMatchers("/admin/**").hasRole("admin")
			.antMatchers("/user/**").hasRole("user")
			.and()
				.formLogin().loginPage("/login.html")//自定义登录页
				.loginProcessingUrl("/login")
				.permitAll()
				.failureForwardUrl("/login.html?error")  // 登录失败 页面
				.defaultSuccessUrl("/login_success", true)
				.usernameParameter("xx")
				.passwordParameter("oo")
//				.successHandler(new AuthenticationSuccessHandler() {
//					@Override
//					public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//						System.out.println("登录成功");
//						Object user = authentication.getPrincipal();
//						System.out.println(user);
//					}
//				})
				.failureHandler(new AuthenticationFailureHandler() {
					@Override
					public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
						// 登录失败
						// 分析失败原因，统计失败次数
					}
				})
			.and()
				.logout().addLogoutHandler(new LogoutHandler() {
					@Override
					public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
						System.out.println("轻轻地我走了");
					}
				}).addLogoutHandler(new LogoutHandler() {
					@Override
					public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
						System.out.println("不带走一片云彩");
					}
			}) //推出逻辑处理器，可以用来清理各种资源
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
				.csrf()
				.csrfTokenRepository(new HttpSessionCsrfTokenRepository()); //不往Cookie里写，往Session里面写。配合前端的<input th:name="${_csrf.parameterName}" th:value="${_csrf.token}" />
			  //.disable();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// session 登录  并发量高 -> jwt (无状态的)。当往Redis里面写的时候已经不能用这个了，必须得用jwt
		auth.inMemoryAuthentication()
				.withUser("111")
				.password(passwordEncoder.encode("123"))
				.roles("admin")
			.and()
				.withUser("112")
				.password(passwordEncoder.encode("123"))
				.roles("user")
			.and()
				.withUser("113")
				.password(passwordEncoder.encode("123"))
				.roles("guest");
	}

	public static void main(String[] args) {
		byte[] decode = Base64.getDecoder().decode("MTIzOjE2MTQ1MDMxODM3NTM6ZjAwYWYzZTJkYjY4MjEwMTUxZDExNjdmMzA2NjE3MDg");
		System.out.println(new String(decode));
	}

	// 及时清理过期的Session，好像有时也用不着
	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher(){
		return new HttpSessionEventPublisher();
	}

	@Bean
	public RoleHierarchy roleHierarchy(){
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		roleHierarchy.setHierarchy("ROLE_admin > ROLE_user");
		return roleHierarchy;
	}
}
