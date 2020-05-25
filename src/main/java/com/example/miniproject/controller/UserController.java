package com.example.miniproject.controller;

import com.example.miniproject.domain.Role;
import com.example.miniproject.domain.User;
import com.example.miniproject.payload.request.LoginRequest;
import com.example.miniproject.payload.request.SignupRequest;
import com.example.miniproject.payload.response.JwtResponse;
import com.example.miniproject.payload.response.MessageResponse;
import com.example.miniproject.repository.UserRepository;
import com.example.miniproject.security.JWT.JwtUtils;
import com.example.miniproject.security.service.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/join")
    public String join() {
        return "join";
    }



}
