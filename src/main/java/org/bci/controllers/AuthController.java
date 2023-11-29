package org.bci.controllers;

import org.bci.dto.request.LoginRequest;
import org.bci.dto.request.UserCreateRequest;
import org.bci.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.validation.Valid;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Controller
public class AuthController {
    public static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);
    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @ResponseBody
    @RequestMapping(value = "/sign-up", method = RequestMethod.POST)
    public ResponseEntity<?> signUp(@RequestBody @Valid UserCreateRequest user) {
        if (!StringUtils.hasLength(user.getEmail()) || !StringUtils.hasLength(user.getPassword())) {
            return new ResponseEntity<>("Please provide a valid username or a password", BAD_REQUEST);
        }
        LOGGER.debug("Hitting [POST] sing-up endpoint with UserCreateRequest: {}", user);
        var userCreated = userService.signUp(user);
        return new ResponseEntity<>(userCreated, CREATED);
    }

    @ResponseBody
    @RequestMapping(value = "/log-in", method = RequestMethod.POST)
    public ResponseEntity<?> logIn(@RequestBody LoginRequest user) {
        try {
            var response = userService.logIn(user);
            LOGGER.debug("Hitting [POST] login endpoint with LoginRequest: {}", user);
            return new ResponseEntity<>(response, OK);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>("Invalid username or password", BAD_REQUEST);
        }
    }
}
