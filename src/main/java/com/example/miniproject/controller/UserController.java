package com.example.miniproject.controller;

import com.example.miniproject.payload.LoginRequest;
import com.example.miniproject.security.JWT.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.http.Cookie;
import javax.validation.Valid;

@Controller
@RequiredArgsConstructor
public class UserController {


    private final AuthenticationManager authenticationManager;

    private final JwtUtils jwtUtils;


    @GetMapping("/login")
    public String login(){
        return "login";
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        Cookie cookie = new Cookie(
                "JWTToken",
                jwtUtils.generateJwtToken(authentication)
        );

        cookie.setPath("/");
        cookie.setMaxAge(Integer.MAX_VALUE);

        return ResponseEntity.ok(cookie);
    }
}
