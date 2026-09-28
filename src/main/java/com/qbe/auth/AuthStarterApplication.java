package com.qbe.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class AuthStarterApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthStarterApplication.class, args);
    }
}
