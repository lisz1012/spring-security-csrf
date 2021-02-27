package com.lisz.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class OkController {
	@GetMapping("/login_success")
	public String ok(){
		return "login_success";
	}
}
