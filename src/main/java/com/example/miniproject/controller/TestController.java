package com.example.miniproject.controller;

//import com.example.miniproject.repository.BoardRepository;

import com.example.miniproject.security.JWT.JwtUtils;
import com.sun.deploy.net.HttpResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

@Controller
@RequestMapping("/test")
@RequiredArgsConstructor
public class TestController {

    private final JwtUtils jwtUtils;
//    private final BoardRepository boardRepository;

    @GetMapping("/all")
    public String allAccess(Model model) {

        return "public_board";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess() {
        return "user_board";
    }

    @GetMapping("/mode")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess() {
        return "mod_board";
    }

    //    @GetMapping("/admin")
//    @PreAuthorize("hasRole('ADMIN')")
//    public ModelAndView adminAccess(ModelAndView modelAndView) {
//        modelAndView = new ModelAndView("admin_board");
//        modelAndView.addObject("message", "Baeldung");
//
//        return modelAndView;
//    }
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {

        return "admin_board";
    }
}

