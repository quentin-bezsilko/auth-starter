package com.qbe.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    OpenAPI openAPI() {
        return new OpenAPI()
                .info(
                        new Info()
                                .title("Spring Starter Auth API")
                                .version("v1")
                                .description(
                                        """
                                Authentication and authorization API providing:
                                - JWT token generation
                                - User authentication
                                - Role and permission management
                                - Token revocation
                                """));
    }
}
