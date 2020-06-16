package com.example.miniproject.payload.response;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpHeaders;

import java.util.List;

@Getter
@Setter
public class SigninResponse {
//    private String token;
//    private String type = "Bearer";
//    private Long id;
//    private String username;
//    private String email;
    private List<String> roles;
    private HttpHeaders headers;

//    public SigninResponse(String accessToken, Long id, String username, String email, List<String> roles, HttpHeaders headers ){
//        this.token = accessToken;
//        this.id = id;
//        this.username = username;
//        this.email = email;
//        this.roles = roles;
//        this.headers = headers;
//    }

    public SigninResponse(List<String> roles, HttpHeaders headers ){
        this.roles = roles;
        this.headers = headers;
    }
}
