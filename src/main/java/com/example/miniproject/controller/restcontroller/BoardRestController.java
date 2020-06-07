package com.example.miniproject.controller.restcontroller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/board/free")
public class BoardRestController {
    @GetMapping("list")
    public ResponseEntity boardList(){

        return new ResponseEntity(HttpStatus.OK);
    }
}
