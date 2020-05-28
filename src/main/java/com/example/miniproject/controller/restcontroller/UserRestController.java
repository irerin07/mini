package com.example.miniproject.controller.restcontroller;

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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserRestController {

    private final AuthenticationManager authenticationManager;

    private final JwtUtils jwtUtils;

    private final UserRepository userRepository;

    private final PasswordEncoder encoder;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid LoginRequest loginRequest, HttpServletResponse response) {
        System.out.println("postmapping signin");
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        System.out.println("authentication");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        System.out.println("generated jwt");

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        System.out.println("userDetails");
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        Cookie cookie = new Cookie(
                "JWTToken",
                jwt
        );
//        UserDetailsImpl userDetails2 = (UserDetailsImpl) authentication.getPrincipal();
//        List<String> roles2 = userDetails.getAuthorities().stream()
//                .map(item -> item.getAuthority())
//                .collect(Collectors.toList());

        cookie.setPath("/");
        cookie.setMaxAge(Integer.MAX_VALUE);

        response.addCookie(cookie);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Location", "/");

        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @PostMapping("/join")
    public ResponseEntity<?> registerUser(@Valid SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: 사용중인 유저이름입니다!"));
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: 사용중인 이메일입니다!"));
        }

        User user = new User(signupRequest.getUsername(),
                signupRequest.getEmail(),
                encoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        return new ResponseEntity<>(HttpStatus.OK);
    }
}
