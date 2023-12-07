package org.bci.handler;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Instant;

import static org.bci.constants.Constants.USER_ALREADY_EXISTS;
import static org.bci.constants.Constants.USER_WAS_NOT_FOUND;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Getter
@AllArgsConstructor
public enum EntityError {

    USER_ALREADY_EXISTS_EXCEPTION_MESSAGE(USER_ALREADY_EXISTS,
            "The email that was provided already have an existing account.",
            Instant.now()),
    USER_NOT_FOUND(USER_WAS_NOT_FOUND,
            "The username that was provided was not found.",
            Instant.now());

    private final String code;
    private final String description;
    private final Instant timestamp;
}
