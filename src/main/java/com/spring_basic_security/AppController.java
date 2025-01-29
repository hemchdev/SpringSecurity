package com.spring_basic_security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AppController {

    @GetMapping("hello")
    public String greet(HttpServletRequest request){
        return "Hi "+ request.getSession().getId();
    }
    @GetMapping("/about")
    public String about(HttpServletRequest request){
        return "Your Session id: "+request.getSession().getId();
    }
}
