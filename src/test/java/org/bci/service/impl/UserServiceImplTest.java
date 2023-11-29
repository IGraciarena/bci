package org.bci.service.impl;

import org.bci.configurations.JwtUtil;
import org.bci.repositories.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.bci.utils.EntityUtils.LOG_IN_REQUEST_STUB;
import static org.bci.utils.EntityUtils.LOG_IN_RESPONSE_STUB;
import static org.bci.utils.EntityUtils.USER_CREATE_REQUEST_STUB;
import static org.bci.utils.EntityUtils.USER_ENTITY_STUB;
import static org.bci.utils.EntityUtils.USER_MODEL_STUB;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @InjectMocks
    private UserServiceImpl userService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtUtil jwtUtil;

    @Test
    void signUp() {
        var actual = USER_ENTITY_STUB;
        when(userRepository.findByEmail(any())).thenReturn(Optional.empty());
        when(userRepository.save(any())).thenReturn(USER_ENTITY_STUB);
        var expected = userService.signUp(USER_CREATE_REQUEST_STUB);
        assertThat(actual.getCreated()).isEqualTo(expected.getCreated());
        assertThat(actual.getId()).isEqualTo(expected.getId());

    }

    @Test
    void logIn() {
        var actual = USER_MODEL_STUB;
        when(userRepository.findByEmail(USER_ENTITY_STUB.getEmail())).thenReturn(
                Optional.of(USER_ENTITY_STUB));
        lenient().when(jwtUtil.createToken(actual)).thenReturn(LOG_IN_RESPONSE_STUB.getToken());
        var expected = userService.logIn(LOG_IN_REQUEST_STUB);
        assertThat(actual.getCreated()).isEqualTo(expected.getCreated());
        assertThat(actual.getId()).isEqualTo(expected.getId());
        assertThat(actual.getName()).isEqualTo(expected.getName());
        assertThat(actual.getEmail()).isEqualTo(expected.getEmail());
        assertThat(actual.getPassword()).isEqualTo(expected.getPassword());
    }
}