package com.qbe.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "User logout request")
public record LogoutRequestDto(
        @Schema(description = "Refresh token to revoke", example = "eyJhbGciOiJSUzI1NiJ9...") @NotBlank
                String refreshToken) {}
