package com.lisz.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class OkController {
	@GetMapping("/ok")
	public String ok(){
		return "ok";
	}
}
