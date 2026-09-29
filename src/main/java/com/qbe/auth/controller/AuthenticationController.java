package com.qbe.auth.controller;

import com.qbe.auth.dto.*;
import com.qbe.auth.service.AuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication, token refresh and logout operations")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    private static final String REFRESH_TOKEN_COOKIE = "refreshToken";

    @Operation(
            summary = "Authenticate a user",
            description =
                    "Authenticates a user using username and password " + "and returns access and refresh tokens.")
    @ApiResponse(responseCode = "200", description = "Authentication successful")
    @ApiResponse(responseCode = "400", description = "Invalid request")
    @ApiResponse(responseCode = "401", description = "Invalid username or password")
    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(@Valid @RequestBody LoginRequestDto request) {

        AuthenticationTokensDto tokens = authenticationService.authenticate(request);
        ResponseCookie refreshTokenCookie = createRefreshTokenCookie(tokens.refreshToken());

        TokenResponseDto response = new TokenResponseDto(tokens.accessToken(), tokens.tokenType(), tokens.expiresIn());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(response);
    }

    @Operation(
            summary = "Refresh an access token",
            description = "Generates a new access token using a valid refresh token.")
    @ApiResponse(responseCode = "200", description = "Token refreshed successfully")
    @ApiResponse(responseCode = "400", description = "Invalid request")
    @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token")
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponseDto> refresh(@CookieValue("refreshToken") String refreshToken) {
        AuthenticationTokensDto tokens = authenticationService.refresh(refreshToken);
        ResponseCookie refreshTokenCookie = createRefreshTokenCookie(tokens.refreshToken());
        TokenResponseDto response = new TokenResponseDto(tokens.accessToken(), tokens.tokenType(), tokens.expiresIn());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(response);
    }

    @Operation(summary = "Logout a user", description = "Revokes the provided refresh token.")
    @ApiResponse(responseCode = "204", description = "Logout successful")
    @ApiResponse(responseCode = "400", description = "Invalid request")
    @ApiResponse(responseCode = "401", description = "Invalid refresh token")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody LogoutRequestDto logoutRequestDto) {
        authenticationService.logout(logoutRequestDto);
        return ResponseEntity.noContent().build();
    }

    private ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE, refreshToken)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .build();
    }
}
