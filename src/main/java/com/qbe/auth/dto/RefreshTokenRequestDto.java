package com.qbe.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Access token refresh request")
public record RefreshTokenRequestDto(
        @Schema(description = "Refresh token used to generate a new access token", example = "eyJhbGciOiJSUzI1NiJ9...")
                @NotBlank
                String refreshToken) {}
