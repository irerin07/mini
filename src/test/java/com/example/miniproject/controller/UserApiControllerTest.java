package com.example.miniproject.controller;

import com.example.miniproject.domain.User;
import com.example.miniproject.payload.request.LoginRequest;
import com.example.miniproject.payload.request.SignupRequest;
import com.example.miniproject.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class UserApiControllerTest {
    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @Before
    public void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

//    @After
//    public void tearDown() throws Exception {
//        userRepository.deleteAll();
//    }

    @Test
    public void 유저_테스트_1() throws Exception {
        //신규 유저 등록 테스트
        //given

        String username = "mytest";
        String password = "359751";
        String email = "mytest@mytest.com";

        SignupRequest signupRequest = SignupRequest.builder()
                .username(username)
                .email(email)
                .password(password)
                .build();

        String url = "http://localhost:" + port + "/api/auth/join";

        //when
        mvc.perform(post(url)
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(signupRequest)))
                .andExpect(status().is3xxRedirection());

        //then
        Optional<User> user = userRepository.findByUsername("mytest");
        assertThat(user.get().getUsername()).isEqualTo(username);
    }

    @Test
    public void 유저_테스트_2() throws Exception{
        //중복 유저 등록 테스트
        String username = "mytest";
        String password = "359751";
        String email = "mytest@mytest.com";

        SignupRequest signupRequest = SignupRequest.builder()
                .username(username)
                .email(email)
                .password(password)
                .build();

        String url = "http://localhost:" + port + "/api/auth/join";

        mvc.perform(post(url)
                .contentType(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(signupRequest)))
                .andExpect(status().isBadRequest());

    }
}
