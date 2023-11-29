package org.bci.handler;

import java.io.Serializable;
import java.time.Instant;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
public interface Error extends Serializable {

    public Integer getCode();


    public String getDescription();

    public Instant getTimestamp();
}
