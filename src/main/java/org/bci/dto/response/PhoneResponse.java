package org.bci.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Getter
@Setter
@EqualsAndHashCode
@Builder(builderClassName = "Builder")
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(force = true)
public class PhoneResponse {
    Long number;

    @JsonProperty("citycode")
    Integer cityCode;

    @JsonProperty("countrycode")
    String countryCode;
}
