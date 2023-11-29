package org.bci.handler;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GenericError implements Error {
    Instant timestamp;
    Integer code;
    String description;
}