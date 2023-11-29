package org.bci.service.impl;

import org.bci.configurations.JwtUtil;
import org.bci.dto.request.LoginRequest;
import org.bci.dto.request.UserCreateRequest;
import org.bci.dto.response.LoginResponse;
import org.bci.dto.response.UserCreateResponse;
import org.bci.entities.UserEntity;
import org.bci.exceptions.EntityNotFoundException;
import org.bci.handler.UniqueEntityAlreadyExistsException;
import org.bci.mapper.PhoneMapper;
import org.bci.mapper.UserMapper;
import org.bci.models.User;
import org.bci.repositories.UserRepository;
import org.bci.service.UserService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;

import static org.bci.handler.EntityError.USER_ALREADY_EXISTS_EXCEPTION_MESSAGE;
import static org.bci.handler.EntityError.USER_NOT_FOUND;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Service
public class UserServiceImpl implements UserService {

    private final PhoneMapper phoneMapper = PhoneMapper.INSTANCE;
    private final UserMapper userMapper = UserMapper.INSTANCE;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    public UserServiceImpl(UserRepository userRepository,
                           JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public UserCreateResponse signUp(UserCreateRequest user) {
        var userFound = userRepository.findByEmail(user.getEmail());
        if (userFound.isPresent()) {
            throw new UniqueEntityAlreadyExistsException(USER_ALREADY_EXISTS_EXCEPTION_MESSAGE);
        }

        var passwordEncoder = new BCryptPasswordEncoder();

        var userSaved = userRepository.save(
                UserEntity.builder()
                        .name(user.getName())
                        .password(passwordEncoder.encode(user.getPassword()))
                        .email(user.getEmail())
                        .created(Instant.now())
                        .phones(phoneMapper.map(user.getPhones()))
                        .build()
        );
        var token = jwtUtil.createToken(userMapper.mapToModel(userSaved));

        return userMapper.map(userSaved, token);
    }

    @Override
    public User getUserByEmail(String userEmail) {
        var user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new EntityNotFoundException(USER_NOT_FOUND));

        return userMapper.mapToModel(user);
    }

    @Override
    public LoginResponse logIn(LoginRequest user) {
        var userFound = getUserByEmail(user.getEmail());
        var token = jwtUtil.createToken(userFound);

        return LoginResponse.builder()
                .id(userFound.getId())
                .name(userFound.getName())
                .token(token)
                .email(userFound.getEmail())
                .password(userFound.getPassword())
                .created(userFound.getCreated())
                .isActive(true)
                .lastLogin(Instant.now())
                .phones(phoneMapper.mapToResponse(userFound.getPhones()))
                .build();
    }
}
