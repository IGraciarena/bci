package org.bci.handler;

import lombok.Getter;
import org.bci.exceptions.ExceptionBase;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Getter
public class UniqueEntityAlreadyExistsException extends ExceptionBase {
    public UniqueEntityAlreadyExistsException(final EntityError error) {
        super(error);
    }
}
