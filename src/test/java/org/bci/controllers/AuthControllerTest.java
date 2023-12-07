package org.bci.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bci.dto.request.LoginRequest;
import org.bci.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.bci.utils.AuthenticationTokenUtils.getBearerToken;
import static org.bci.utils.EntityUtils.LOG_IN_REQUEST_STUB;
import static org.bci.utils.EntityUtils.LOG_IN_RESPONSE_STUB;
import static org.bci.utils.EntityUtils.USER_CREATE_REQUEST_STUB;
import static org.bci.utils.EntityUtils.USER_CREATE_RESPONSE_STUB;
import static org.bci.utils.EntityUtils.USER_ENTITY_STUB;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    UserService userService;

    @Test
    void signUp() throws Exception {
        when(userService.signUp(USER_CREATE_REQUEST_STUB))
                .thenReturn(USER_CREATE_RESPONSE_STUB);
        var request = LoginRequest.builder()
                .email(USER_ENTITY_STUB.getEmail())
                .password(USER_ENTITY_STUB.getPassword()).build();

        this.mockMvc.perform(post("/api/sign-up")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(request)))
                .andExpect(status().isCreated());
    }

    @Test
    void logIn() throws Exception {
        when(userService.logIn(LOG_IN_REQUEST_STUB))
                .thenReturn(LOG_IN_RESPONSE_STUB);
        var request = LoginRequest.builder()
                .email(USER_ENTITY_STUB.getEmail())
                .password(USER_ENTITY_STUB.getPassword())
                .build();
        this.mockMvc.perform(post("/api/log-in")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(asJsonString(request))
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + getBearerToken()))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }

    private static String asJsonString(final Object obj) {
        try {
            return new ObjectMapper().writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}