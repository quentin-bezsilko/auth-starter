package com.qbe.auth.properties;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.security.jwt")
public record JwtProperties(
        String issuer, String audience, Duration accessTokenDuration, Duration refreshTokenDuration) {}
