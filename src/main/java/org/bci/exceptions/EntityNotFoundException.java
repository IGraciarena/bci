package org.bci.exceptions;

import lombok.Getter;
import org.bci.handler.EntityError;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Getter
public class EntityNotFoundException extends ExceptionBase {

    private static final long serialVersionUID = 962237408315663159L;

    public EntityNotFoundException(final EntityError error) {
        super(error);
    }
}
