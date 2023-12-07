package org.bci.handler;

import io.jsonwebtoken.ExpiredJwtException;
import org.bci.exceptions.EntityNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.Instant;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@ControllerAdvice
public class RestResponseExceptionHandler {

    public static final Logger LOGGER = LoggerFactory.getLogger(RestResponseExceptionHandler.class);

    @ExceptionHandler({EntityNotFoundException.class})
    public ResponseEntity<?> handleEntityNotFoundException(EntityNotFoundException ex) {
        GenericError errorResponse = new GenericError(
                Instant.now(),
                HttpStatus.NOT_FOUND.value(),
                "Entity was not found");
        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler({ExpiredJwtException.class})
    public ResponseEntity<?> handleExpiredJwtException(ExpiredJwtException ex) {
        GenericError errorResponse = new GenericError(
                Instant.now(),
                HttpStatus.UNAUTHORIZED.value(),
                "JWT is expired.");
        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler({UniqueEntityAlreadyExistsException.class})
    public ResponseEntity<?> handleUniqueEntityAlreadyExistsException(UniqueEntityAlreadyExistsException ex) {
        LOGGER.error("{} - {}", ex.getError().getCode(), ex.getError().getDescription());
        GenericError errorResponse = new GenericError(
                Instant.now(),
                HttpStatus.BAD_REQUEST.value(),
                "Entity Already exists");
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleException(Exception ex) {
        GenericError errorResponse = new GenericError(
                Instant.now(),
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Unexpected error occurred");
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
