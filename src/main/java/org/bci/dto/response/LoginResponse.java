package org.bci.dto.response;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.Value;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Value
@EqualsAndHashCode
@Builder(builderClassName = "Builder")
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(force = true)
public class LoginResponse {
    UUID id;
    Instant created;
    Instant lastLogin;
    String token;
    boolean isActive;
    String name;
    String email;
    String password;
    List<PhoneResponse> phones;
}
