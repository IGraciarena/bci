package org.bci.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.bci.dto.request.LoginRequest;
import org.bci.dto.request.UserCreateRequest;
import org.bci.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springdoc.api.annotations.ParameterObject;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.validation.Valid;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Controller
@RequestMapping("/api")
@Tag(name = "User API")
public class AuthController {
    public static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);
    public final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @Operation(summary = "Sign up a new User.", description = "Sign up a new user with a valid UserCreateRequest.",
            responses = {
                    @ApiResponse(responseCode = "201", description = "CREATED",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
                    @ApiResponse(responseCode = "400", description = "BAD_REQUEST",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
                    @ApiResponse(responseCode = "500", description = "INTERNAL_SERVER_ERROR",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE))
            })
    @PostMapping(value = "/sign-up")
    public ResponseEntity<?> signUp(@ParameterObject @RequestBody @Valid UserCreateRequest user) {
        if (!StringUtils.hasLength(user.getEmail()) || !StringUtils.hasLength(user.getPassword())) {
            return new ResponseEntity<>("Please provide a valid username or a password", BAD_REQUEST);
        }
        LOGGER.debug("Hitting [POST] sing-up endpoint with UserCreateRequest: {}", user);
        var userCreated = userService.signUp(user);
        return new ResponseEntity<>(userCreated, CREATED);
    }

    @Operation(summary = "Log in a User.", description = "Log in a User passing JWT bearer Token.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "OK",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
                    @ApiResponse(responseCode = "400", description = "BAD_REQUEST",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
                    @ApiResponse(responseCode = "401", description = "UNAUTHORIZED",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE)),
                    @ApiResponse(responseCode = "500", description = "INTERNAL_SERVER_ERROR",
                            content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE))
            })
    @PostMapping(value = "/log-in")
    public ResponseEntity<?> logIn(@ParameterObject @RequestBody LoginRequest user) {
        var response = userService.logIn(user);
        LOGGER.debug("Hitting [POST] log-in endpoint with LoginRequest: {}", user);
        return new ResponseEntity<>(response, OK);
    }
}
