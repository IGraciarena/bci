package org.bci.service;

import org.bci.dto.request.LoginRequest;
import org.bci.dto.request.UserCreateRequest;
import org.bci.dto.response.LoginResponse;
import org.bci.dto.response.UserCreateResponse;
import org.bci.models.User;
import org.springframework.stereotype.Service;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Service
public interface UserService {

    UserCreateResponse signUp(UserCreateRequest user);

    User getUserByEmail(String userEmail);

    LoginResponse logIn(LoginRequest user);
}
