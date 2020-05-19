//package com.example.miniproject.controller;
//
//import com.example.miniproject.security.JWT.JwtUtils;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.stereotype.Controller;
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.CookieValue;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//
//@Controller
//@RequestMapping("/test")
//@RequiredArgsConstructor
//public class TestController {
//
//    private final JwtUtils jwtUtils;
//
//    @GetMapping("/token")
////    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
//    public String token(Model model, @CookieValue(value = "JWTToken", defaultValue = "Atta") String JWTToken){
//        if(jwtUtils.validateJwtToken(JWTToken)) {
//            String username = jwtUtils.getUserNameFromJwtToken(JWTToken);
//            model.addAttribute("token", JWTToken);
//            model.addAttribute("username", username);
//            return "token";
//        }
//        return "login";
//    }
//    @GetMapping("/all")
//    public String allAccess() {
//        return "public_board";
//    }
//
//    @GetMapping("/user")
//    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
//    public String userAccess() {
//        return "user_board";
//    }
//
//    @GetMapping("/mod")
//    @PreAuthorize("hasRole('MODERATOR')")
//    public String moderatorAccess() {
//        return "mod_board";
//    }
//
//    @GetMapping("/admin")
//    @PreAuthorize("hasRole('ADMIN')")
//    public String adminAccess() {
//        return "admin_board";
//    }
//}
