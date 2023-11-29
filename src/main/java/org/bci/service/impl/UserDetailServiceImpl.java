package org.bci.service.impl;

import org.bci.configurations.UserConfigurationToken;
import org.bci.exceptions.EntityNotFoundException;
import org.bci.repositories.UserRepository;
import org.bci.service.UserDetailService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import static org.bci.handler.EntityError.USER_NOT_FOUND;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Service
public class UserDetailServiceImpl implements UserDetailService {

    private final UserRepository userRepository;

    public UserDetailServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException(USER_NOT_FOUND));

        return new UserConfigurationToken(user.getEmail(), user.getPassword());
    }
}
