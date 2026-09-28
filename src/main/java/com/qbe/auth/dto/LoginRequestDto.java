package com.qbe.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "User authentication request")
public record LoginRequestDto(
        @Schema(description = "Username used for authentication", example = "admin") @NotBlank String username,
        @Schema(description = "User password", example = "password", format = "password") @NotBlank String password) {}
