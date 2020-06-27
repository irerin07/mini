package com.example.miniproject.controller.restcontroller;

import com.example.miniproject.payload.request.BoardRequest;
import com.example.miniproject.payload.request.LoginRequest;
import com.example.miniproject.security.JWT.AuthTokenFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/board")
public class BoardRestController {
    @GetMapping("/admin")
    public ModelAndView boardList(ModelAndView model) {
        model.addObject("Model", model);

        return model;
    }

}
