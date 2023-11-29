package org.bci.exceptions;

import lombok.Getter;
import org.bci.handler.EntityError;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Getter
public class ExceptionBase extends RuntimeException {

    private final EntityError error;

    public ExceptionBase(EntityError error) {
        this.error = error;
    }
}
