package com.qbe.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Authentication tokens")
public record TokenResponseDto(
        @Schema(
                        description = "JWT access token used to access protected resources",
                        example = "eyJhbGciOiJSUzI1NiJ9...")
                String accessToken,
        @Schema(description = "Refresh token used to obtain a new access token", example = "eyJhbGciOiJSUzI1NiJ9...")
                String refreshToken,
        @Schema(description = "Token type", example = "Bearer") String tokenType,
        @Schema(description = "Access token lifetime in seconds", example = "3600") long expiresIn) {}
