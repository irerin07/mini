package com.example.miniproject.controller.restcontroller;

import com.example.miniproject.payload.request.BoardRequest;
import com.example.miniproject.payload.request.LoginRequest;
import com.example.miniproject.security.JWT.AuthTokenFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
@RequestMapping("/test")
public class BoardRestController {

    AuthTokenFilter authTokenFilter;

    @GetMapping("/admin")
//    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity adminAccess(@CookieValue("JWTToken") String fooCookie, @Valid HttpServletRequest request, HttpServletResponse response) {
//        String headerAuth = request.getHeader("JWTToken");
        System.out.println(fooCookie);

        return new ResponseEntity(HttpStatus.OK);
    }
}
