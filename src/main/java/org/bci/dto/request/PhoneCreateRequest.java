package org.bci.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.Value;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Value
@EqualsAndHashCode
@Builder(builderClassName = "Builder")
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(force = true)
public class PhoneCreateRequest {
    Long number;

    @JsonProperty("citycode")
    Integer cityCode;

    @JsonProperty("countrycode")
    String countryCode;
}
