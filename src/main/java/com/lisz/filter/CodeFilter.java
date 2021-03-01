package com.lisz.filter;

import com.google.code.kaptcha.Constants;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CodeFilter implements Filter {
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest)request;
		HttpServletResponse resp = (HttpServletResponse) response;
		// 当前用户请求的URL，看看是不是登录接口
		String uri = req.getServletPath();
		if (uri.equals("/login") && req.getMethod().equalsIgnoreCase("post")){
			String sessionCode = req.getSession().getAttribute(Constants.KAPTCHA_SESSION_KEY).toString();
			String formCode = req.getParameter("code").trim();
			if (StringUtils.isEmpty(formCode)){
				throw new IllegalArgumentException("验证码不能为空");
			}
			if (sessionCode.equalsIgnoreCase(formCode)) {
				System.out.println("验证通过");
			} else {
				throw new RuntimeException("验证码错误");
			}
		}
		chain.doFilter(request, response);
	}
}
