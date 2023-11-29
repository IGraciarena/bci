package org.bci.dto.request;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.Value;

import javax.validation.constraints.Email;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Value
@EqualsAndHashCode
@Builder(builderClassName = "Builder")
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(force = true)
public class LoginRequest {

    @Email
    String email;

    @Size(min = 8, max = 12, message = "Password length must be between 8 and 12 characters")
    @Pattern(regexp = "^(?=.*[A-Z])(?=.*[0-9].*[0-9])(?!.*[^a-zA-Z0-9]).{8,12}$", message = "Invalid password format")
    String password;
}
