package org.bci.configurations;

import org.springdoc.core.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Configuration
public class ApiConfiguration {
    @Bean
    public GroupedOpenApi groupedOpenApi() {
        return GroupedOpenApi.builder()
                .group("api")
                .pathsToMatch("/api/**") // Set the path to match for this API
                .build();
    }
}
