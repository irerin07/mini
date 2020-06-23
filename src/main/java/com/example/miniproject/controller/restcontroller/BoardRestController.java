package com.example.miniproject.controller.restcontroller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/board")
public class BoardRestController {
    @GetMapping("/admin")
    public ResponseEntity boardList(Model model){
        model.addAttribute("Model", model);

        return new ResponseEntity(HttpStatus.OK);
    }
}
