package com.qbe.auth.properties;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app.security.keys")
public record KeyProperties(@NotNull Resource publicKey, @NotNull Resource privateKey) {}
